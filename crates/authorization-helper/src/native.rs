//! Supported ServiceManagement registration and code-bound, bounded XPC.
//! No shell, caller-selected file path, output path or model operation is exposed.

use crate::{
    APP_ID, MAX_STATE_BYTES, NONCE_BYTES, PLIST, Problem, SERVICE, Snapshot, Source, StateFile,
    Status,
};
use block2::{Block, RcBlock};
use objc2::{
    msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, Bool},
};
use objc2_foundation::NSString;
use std::{
    ffi::{CStr, CString, c_void},
    ptr::{self, NonNull},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Raw = *mut c_void;
type Handler = Block<dyn Fn(Raw)>;

#[link(name = "ServiceManagement", kind = "framework")]
unsafe extern "C" {}
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static _xpc_error_peer_code_signing_requirement: c_void;
    fn SCDynamicStoreCopyConsoleUser(store: Raw, uid: *mut u32, gid: *mut u32) -> Raw;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(object: Raw);
}

unsafe extern "C" {
    static _xpc_type_dictionary: c_void;
    static _xpc_type_connection: c_void;
    static _xpc_type_uint64: c_void;
    static _xpc_type_string: c_void;
    fn xpc_get_type(object: Raw) -> *const c_void;
    fn xpc_release(object: Raw);
    fn xpc_dictionary_create(
        keys: *const *const libc::c_char,
        values: *const Raw,
        count: usize,
    ) -> Raw;
    fn xpc_dictionary_create_reply(message: Raw) -> Raw;
    fn xpc_dictionary_get_count(object: Raw) -> usize;
    fn xpc_dictionary_get_value(object: Raw, key: *const libc::c_char) -> Raw;
    fn xpc_dictionary_get_uint64(object: Raw, key: *const libc::c_char) -> u64;
    fn xpc_dictionary_set_uint64(object: Raw, key: *const libc::c_char, value: u64);
    fn xpc_dictionary_get_string(object: Raw, key: *const libc::c_char) -> *const libc::c_char;
    fn xpc_string_get_length(object: Raw) -> usize;
    fn xpc_dictionary_set_string(object: Raw, key: *const libc::c_char, value: *const libc::c_char);
    fn xpc_dictionary_get_data(
        object: Raw,
        key: *const libc::c_char,
        length: *mut usize,
    ) -> *const c_void;
    fn xpc_dictionary_set_data(
        object: Raw,
        key: *const libc::c_char,
        data: *const c_void,
        length: usize,
    );
    fn xpc_dictionary_get_remote_connection(object: Raw) -> Raw;
    fn xpc_connection_create_mach_service(name: *const libc::c_char, queue: Raw, flags: u64)
    -> Raw;
    fn xpc_connection_set_peer_code_signing_requirement(
        connection: Raw,
        requirement: *const libc::c_char,
    ) -> i32;
    fn xpc_connection_set_event_handler(connection: Raw, handler: &Handler);
    fn xpc_connection_activate(connection: Raw);
    fn xpc_connection_cancel(connection: Raw);
    fn xpc_connection_get_euid(connection: Raw) -> u32;
    fn xpc_connection_send_message(connection: Raw, message: Raw);
    fn xpc_connection_send_message_with_reply(
        connection: Raw,
        message: Raw,
        queue: Raw,
        handler: &Handler,
    );
    fn dispatch_main() -> !;
}

struct Object(NonNull<c_void>);
impl Object {
    // Every constructor call below receives a +1 object from an XPC create API.
    unsafe fn owned(raw: Raw) -> Result<Self, Problem> {
        NonNull::new(raw).map(Self).ok_or(Problem::Unavailable)
    }
    fn raw(&self) -> Raw {
        self.0.as_ptr()
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            xpc_release(self.raw());
        }
    }
}
struct Connection(Object);
impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            xpc_connection_cancel(self.0.raw());
        }
    }
}

fn configured_team() -> Result<&'static str, Problem> {
    let team = option_env!("IPATOOL_AUTHORIZATION_TEAM").ok_or(Problem::SigningRequired)?;
    if team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(Problem::SigningRequired);
    }
    Ok(team)
}

fn requirement(team: &str, app: bool) -> Result<CString, Problem> {
    if team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(Problem::SigningRequired);
    }
    let identifier = if app { APP_ID } else { SERVICE };
    CString::new(format!("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{team}\" and identifier \"{identifier}\"" )).map_err(|_|Problem::SigningRequired)
}

fn service() -> Result<Retained<AnyObject>, Problem> {
    let class = AnyClass::get(c"SMAppService").ok_or(Problem::Unsupported)?;
    configured_team()?;
    let bundle = AnyClass::get(c"NSBundle").ok_or(Problem::Unsupported)?;
    // SAFETY: Foundation's class/property selectors have the declared signatures.
    let main: Retained<AnyObject> = unsafe { msg_send![bundle, mainBundle] };
    let identifier: Option<Retained<NSString>> = unsafe { msg_send![&*main, bundleIdentifier] };
    if identifier.as_ref().map(|s| s.to_string()).as_deref() != Some(APP_ID) {
        return Err(Problem::SigningRequired);
    }
    let plist = NSString::from_str(PLIST);
    let value: Option<Retained<AnyObject>> =
        unsafe { msg_send![class,daemonServiceWithPlistName:&*plist] };
    value.ok_or(Problem::Unavailable)
}

fn service_status(value: &AnyObject) -> Status {
    let status: isize = unsafe { msg_send![value, status] };
    match status {
        0 => Status::NotRegistered,
        1 => Status::Enabled,
        2 => Status::RequiresApproval,
        _ => Status::NotFound,
    }
}
pub fn status() -> Status {
    objc2::rc::autoreleasepool(|_| match service() {
        Ok(service) => service_status(&service),
        Err(Problem::SigningRequired) => Status::SigningRequired,
        Err(_) => Status::Unsupported,
    })
}
pub fn register() -> Result<Status, Problem> {
    objc2::rc::autoreleasepool(|_| {
        let service = service()?;
        let current = service_status(&service);
        if matches!(current, Status::Enabled | Status::RequiresApproval) {
            return Ok(current);
        }
        // No NSError is logged or persisted; only the checked service state escapes.
        let ok: Bool = unsafe {
            msg_send![&*service,registerAndReturnError:ptr::null_mut::<*mut objc2_foundation::NSError>()]
        };
        let status = service_status(&service);
        if ok.as_bool() || matches!(status, Status::RequiresApproval | Status::Enabled) {
            Ok(status)
        } else {
            Err(Problem::Unavailable)
        }
    })
}
pub fn unregister() -> Result<Status, Problem> {
    objc2::rc::autoreleasepool(|_| {
        let service = service()?;
        if service_status(&service) == Status::NotRegistered {
            return Ok(Status::NotRegistered);
        }
        let ok: Bool = unsafe {
            msg_send![&*service,unregisterAndReturnError:ptr::null_mut::<*mut objc2_foundation::NSError>()]
        };
        if ok.as_bool() {
            Ok(service_status(&service))
        } else {
            Err(Problem::Unavailable)
        }
    })
}
pub fn open_settings() -> Result<(), Problem> {
    objc2::rc::autoreleasepool(|_| {
        service()?;
        let class = AnyClass::get(c"SMAppService").ok_or(Problem::Unsupported)?;
        unsafe {
            let _: () = msg_send![class, openSystemSettingsLoginItems];
        }
        Ok(())
    })
}

fn dictionary(raw: Raw) -> bool {
    !raw.is_null() && unsafe { xpc_get_type(raw) == ptr::addr_of!(_xpc_type_dictionary) }
}
fn number(raw: Raw, key: &CStr) -> Option<u64> {
    let value = unsafe { xpc_dictionary_get_value(raw, key.as_ptr()) };
    (!value.is_null() && unsafe { xpc_get_type(value) == ptr::addr_of!(_xpc_type_uint64) })
        .then(|| unsafe { xpc_dictionary_get_uint64(raw, key.as_ptr()) })
}
fn text_is(raw: Raw, key: &CStr, expected: &CStr) -> bool {
    let value = unsafe { xpc_dictionary_get_value(raw, key.as_ptr()) };
    if value.is_null()
        || unsafe {
            xpc_get_type(value) != ptr::addr_of!(_xpc_type_string)
                || xpc_string_get_length(value) > 32
        }
    {
        return false;
    }
    let string = unsafe { xpc_dictionary_get_string(raw, key.as_ptr()) };
    !string.is_null() && unsafe { CStr::from_ptr(string) } == expected
}
fn data(raw: Raw, key: &CStr, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>, Problem> {
    let mut length = 0;
    let value = unsafe { xpc_dictionary_get_data(raw, key.as_ptr(), &mut length) };
    if value.is_null() {
        return Ok(None);
    }
    if length > limit {
        return Err(Problem::InvalidRequest);
    }
    // SAFETY: XPC owns this bounded view for the current callback. Return an
    // owned, wiping snapshot; no unconstrained borrowed lifetime escapes.
    let bytes = unsafe { std::slice::from_raw_parts(value.cast(), length) };
    Ok(Some(Zeroizing::new(bytes.to_vec())))
}

fn key(source: Source) -> &'static CStr {
    match source {
        Source::System => c"system",
        Source::Shared => c"shared",
    }
}

fn parse_reply(raw: Raw, nonce: &[u8; NONCE_BYTES]) -> Result<Snapshot, Problem> {
    if raw.cast_const() == ptr::addr_of!(_xpc_error_peer_code_signing_requirement) {
        return Err(Problem::SigningRequired);
    }
    if !dictionary(raw) {
        return Err(Problem::Unavailable);
    }
    if data(raw, c"nonce", NONCE_BYTES)?
        .as_ref()
        .map(|bytes| bytes.as_slice())
        != Some(nonce.as_slice())
    {
        return Err(Problem::InvalidRequest);
    }
    let code = number(raw, c"status").ok_or(Problem::InvalidRequest)?;
    if code != 0 {
        return Err(Problem::from_code(code));
    }
    let mut files = Vec::new();
    for source in Source::ALL {
        if let Some(bytes) = data(raw, key(source), MAX_STATE_BYTES)? {
            files.push(StateFile { source, bytes });
        }
    }
    if unsafe { xpc_dictionary_get_count(raw) } != 2 + files.len() {
        return Err(Problem::InvalidRequest);
    }
    Snapshot::checked(files)
}

pub fn request_snapshot(cancel: impl Fn() -> bool) -> Result<Snapshot, Problem> {
    if cancel() {
        return Err(Problem::Cancelled);
    }
    match status() {
        Status::Enabled => {}
        Status::SigningRequired => return Err(Problem::SigningRequired),
        Status::Unsupported => return Err(Problem::Unsupported),
        _ => return Err(Problem::ApprovalRequired),
    }
    let requirement = requirement(configured_team()?, false)?;
    let name = CString::new(SERVICE).expect("fixed service name");
    let connection = Connection(unsafe {
        Object::owned(xpc_connection_create_mach_service(
            name.as_ptr(),
            ptr::null_mut(),
            2,
        ))?
    });
    if unsafe {
        xpc_connection_set_peer_code_signing_requirement(connection.0.raw(), requirement.as_ptr())
    } != 0
    {
        return Err(Problem::SigningRequired);
    }
    let handler = RcBlock::new(|_: Raw| {});
    unsafe {
        xpc_connection_set_event_handler(connection.0.raw(), &handler);
        xpc_connection_activate(connection.0.raw());
    }
    let request = unsafe { Object::owned(xpc_dictionary_create(ptr::null(), ptr::null(), 0))? };
    let mut nonce = [0u8; NONCE_BYTES];
    unsafe {
        libc::arc4random_buf(nonce.as_mut_ptr().cast(), nonce.len());
        xpc_dictionary_set_uint64(request.raw(), c"version".as_ptr(), 1);
        xpc_dictionary_set_string(request.raw(), c"operation".as_ptr(), c"snapshot".as_ptr());
        xpc_dictionary_set_data(
            request.raw(),
            c"nonce".as_ptr(),
            nonce.as_ptr().cast(),
            nonce.len(),
        );
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let reply = RcBlock::new(move |raw: Raw| {
        let _ = sender.send(parse_reply(raw, &nonce));
    });
    // SAFETY: the escaping block captures only a Send/Sync channel and owned
    // nonce. XPC retains it and keeps each borrowed reply live for this call.
    unsafe {
        xpc_connection_send_message_with_reply(
            connection.0.raw(),
            request.raw(),
            ptr::null_mut(),
            &reply,
        );
    }
    let started = Instant::now();
    loop {
        if cancel() {
            return Err(Problem::Cancelled);
        }
        if started.elapsed() > Duration::from_secs(15) {
            return Err(Problem::Unavailable);
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(reply) => return reply,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(Problem::Unavailable),
        }
    }
}

fn console_uid() -> Result<u32, Problem> {
    let mut uid = u32::MAX;
    let mut gid = u32::MAX;
    let name = unsafe { SCDynamicStoreCopyConsoleUser(ptr::null_mut(), &mut uid, &mut gid) };
    if name.is_null() {
        return Err(Problem::NotConsoleUser);
    }
    unsafe {
        CFRelease(name);
    }
    if uid <= 500 || uid == u32::MAX {
        return Err(Problem::NotConsoleUser);
    }
    Ok(uid)
}

fn validate_request(raw: Raw) -> Result<(), Problem> {
    if !dictionary(raw)
        || unsafe { xpc_dictionary_get_count(raw) } != 3
        || number(raw, c"version") != Some(1)
        || !text_is(raw, c"operation", c"snapshot")
        || !data(raw, c"nonce", NONCE_BYTES)?.is_some_and(|bytes| bytes.len() == NONCE_BYTES)
    {
        return Err(Problem::InvalidRequest);
    }
    Ok(())
}

static BUSY: AtomicBool = AtomicBool::new(false);
fn serve_message(raw: Raw) {
    if !dictionary(raw) {
        return;
    }
    let mut nonce = [0; NONCE_BYTES];
    if let Ok(Some(bytes)) = data(raw, c"nonce", NONCE_BYTES)
        && bytes.len() == NONCE_BYTES
    {
        nonce.copy_from_slice(&bytes);
    }
    let result = (|| {
        validate_request(raw)?;
        let peer = unsafe { xpc_dictionary_get_remote_connection(raw) };
        let uid = console_uid()?;
        if peer.is_null() || unsafe { xpc_connection_get_euid(peer) } != uid {
            return Err(Problem::NotConsoleUser);
        }
        if BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Problem::Unavailable);
        }
        struct Release;
        impl Drop for Release {
            fn drop(&mut self) {
                BUSY.store(false, Ordering::Release);
            }
        }
        let _release = Release;
        let snapshot = crate::files::read_for_user(uid)?;
        if console_uid()? != uid {
            return Err(Problem::NotConsoleUser);
        }
        Ok(snapshot)
    })();
    let Ok(reply) = (unsafe { Object::owned(xpc_dictionary_create_reply(raw)) }) else {
        return;
    };
    unsafe {
        xpc_dictionary_set_data(
            reply.raw(),
            c"nonce".as_ptr(),
            nonce.as_ptr().cast(),
            nonce.len(),
        );
        xpc_dictionary_set_uint64(
            reply.raw(),
            c"status".as_ptr(),
            result.as_ref().err().map_or(0, |error| error.code()),
        );
    }
    if let Ok(snapshot) = &result {
        for file in &snapshot.files {
            unsafe {
                xpc_dictionary_set_data(
                    reply.raw(),
                    key(file.source).as_ptr(),
                    file.bytes.as_ptr().cast(),
                    file.bytes.len(),
                );
            }
        }
    }
    let peer = unsafe { xpc_dictionary_get_remote_connection(raw) };
    if !peer.is_null() {
        unsafe {
            xpc_connection_send_message(peer, reply.raw());
        }
    }
}

pub fn run_helper() -> Result<(), Problem> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Problem::NotConsoleUser);
    }
    let listener_requirement = requirement(configured_team()?, true)?;
    let name = CString::new(SERVICE).expect("fixed service");
    let listener = Connection(unsafe {
        Object::owned(xpc_connection_create_mach_service(
            name.as_ptr(),
            ptr::null_mut(),
            1,
        ))?
    });
    if unsafe {
        xpc_connection_set_peer_code_signing_requirement(
            listener.0.raw(),
            listener_requirement.as_ptr(),
        )
    } != 0
    {
        return Err(Problem::SigningRequired);
    }
    let handler = RcBlock::new(|peer: Raw| {
        if peer.is_null() || unsafe { xpc_get_type(peer) != ptr::addr_of!(_xpc_type_connection) } {
            return;
        }
        let Ok(peer_requirement) = configured_team().and_then(|team| requirement(team, true))
        else {
            unsafe {
                xpc_connection_cancel(peer);
            }
            return;
        };
        if unsafe {
            xpc_connection_set_peer_code_signing_requirement(peer, peer_requirement.as_ptr())
        } != 0
        {
            unsafe {
                xpc_connection_cancel(peer);
            }
            return;
        }
        let handler = RcBlock::new(serve_message);
        // SAFETY: XPC owns the accepted peer through its invalidation event.
        // Neither block captures a borrowed peer or an owned connection cycle.
        unsafe {
            xpc_connection_set_event_handler(peer, &handler);
            xpc_connection_activate(peer);
        }
    });
    unsafe {
        xpc_connection_set_event_handler(listener.0.raw(), &handler);
        xpc_connection_activate(listener.0.raw());
        dispatch_main();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecRequirementCreateWithString(text: Raw, flags: u32, requirement: *mut Raw) -> i32;
        fn SecCodeCopySelf(flags: u32, code: *mut Raw) -> i32;
        fn SecCodeCheckValidity(code: Raw, flags: u32, requirement: Raw) -> i32;
    }

    #[test]
    fn system_code_requirement_parser_accepts_both_policies_and_rejects_this_test_peer() {
        objc2::rc::autoreleasepool(|_| {
            let mut code = ptr::null_mut();
            assert_eq!(unsafe { SecCodeCopySelf(0, &mut code) }, 0);
            assert!(!code.is_null());
            for app in [false, true] {
                let policy = requirement("A1B2C3D4E5", app).unwrap();
                let text = NSString::from_str(policy.to_str().unwrap());
                let mut parsed = ptr::null_mut();
                assert_eq!(
                    unsafe {
                        SecRequirementCreateWithString(
                            (&*text as *const NSString).cast_mut().cast(),
                            0,
                            &mut parsed,
                        )
                    },
                    0
                );
                assert!(!parsed.is_null());
                assert_ne!(unsafe { SecCodeCheckValidity(code, 0, parsed) }, 0);
                unsafe { CFRelease(parsed) };
            }
            unsafe { CFRelease(code) };
        });
    }

    #[test]
    fn requirements_are_fixed_developer_id_peers_not_caller_supplied_identifiers() {
        let value = requirement("A1B2C3D4E5", true).unwrap();
        assert!(value.to_str().unwrap().contains(APP_ID));
        assert!(value.to_str().unwrap().contains("100.6.1.13"));
        assert!(
            requirement("A1B2C3D4E5", false)
                .unwrap()
                .to_str()
                .unwrap()
                .contains(SERVICE)
        );
        for invalid in ["", "A1B2C3D4E5\" or true", "a1b2c3d4e5", "A1B2C3D4E55"] {
            assert!(requirement(invalid, true).is_err());
        }
    }
    #[test]
    fn wire_replies_are_nonce_bound_and_unknown_or_oversize_values_are_rejected() {
        let value =
            unsafe { Object::owned(xpc_dictionary_create(ptr::null(), ptr::null(), 0)).unwrap() };
        let nonce = [0x51; NONCE_BYTES];
        let state = [0u8, 7, 0, 11];
        unsafe {
            xpc_dictionary_set_data(
                value.raw(),
                c"nonce".as_ptr(),
                nonce.as_ptr().cast(),
                nonce.len(),
            );
            xpc_dictionary_set_uint64(value.raw(), c"status".as_ptr(), 0);
            xpc_dictionary_set_data(
                value.raw(),
                c"system".as_ptr(),
                state.as_ptr().cast(),
                state.len(),
            );
        }
        assert_eq!(parse_reply(value.raw(), &nonce).unwrap().files.len(), 1);
        assert_eq!(
            parse_reply(value.raw(), &[0; NONCE_BYTES]).err(),
            Some(Problem::InvalidRequest)
        );
        unsafe {
            xpc_dictionary_set_uint64(value.raw(), c"extra".as_ptr(), 1);
        }
        assert_eq!(
            parse_reply(value.raw(), &nonce).err(),
            Some(Problem::InvalidRequest)
        );
        let value =
            unsafe { Object::owned(xpc_dictionary_create(ptr::null(), ptr::null(), 0)).unwrap() };
        let excessive = vec![0u8; MAX_STATE_BYTES + 1];
        unsafe {
            xpc_dictionary_set_data(
                value.raw(),
                c"nonce".as_ptr(),
                nonce.as_ptr().cast(),
                nonce.len(),
            );
            xpc_dictionary_set_uint64(value.raw(), c"status".as_ptr(), 0);
            xpc_dictionary_set_data(
                value.raw(),
                c"system".as_ptr(),
                excessive.as_ptr().cast(),
                excessive.len(),
            );
        }
        assert_eq!(
            parse_reply(value.raw(), &nonce).err(),
            Some(Problem::InvalidRequest)
        );
    }

    #[test]
    fn requests_never_accept_paths_commands_extra_fields_or_other_versions() {
        let value =
            unsafe { Object::owned(xpc_dictionary_create(ptr::null(), ptr::null(), 0)).unwrap() };
        let nonce = [0u8; NONCE_BYTES];
        unsafe {
            xpc_dictionary_set_data(
                value.raw(),
                c"nonce".as_ptr(),
                nonce.as_ptr().cast(),
                nonce.len(),
            );
            xpc_dictionary_set_uint64(value.raw(), c"version".as_ptr(), 1);
            xpc_dictionary_set_string(value.raw(), c"operation".as_ptr(), c"snapshot".as_ptr());
        }
        validate_request(value.raw()).unwrap();
        unsafe {
            xpc_dictionary_set_uint64(value.raw(), c"version".as_ptr(), 2);
        }
        assert_eq!(validate_request(value.raw()), Err(Problem::InvalidRequest));
        unsafe {
            xpc_dictionary_set_uint64(value.raw(), c"version".as_ptr(), 1);
            xpc_dictionary_set_string(value.raw(), c"operation".as_ptr(), c"execute".as_ptr());
        }
        assert_eq!(validate_request(value.raw()), Err(Problem::InvalidRequest));
        unsafe {
            xpc_dictionary_set_string(value.raw(), c"operation".as_ptr(), c"snapshot".as_ptr());
            xpc_dictionary_set_string(value.raw(), c"path".as_ptr(), c"/etc/passwd".as_ptr());
        }
        assert_eq!(validate_request(value.raw()), Err(Problem::InvalidRequest));
    }
}
