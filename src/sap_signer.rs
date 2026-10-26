//! SAP signer session lifecycle over a guest runtime and setup protocol.

use anyhow::{Context, Result, bail};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{SapConfig, validate_sap_config},
    sap_protocol::{SapHttpClient, SapProtocol},
};

pub trait SapGuest {
    fn initialize(&mut self, hardware_id: &[u8]) -> Result<u64>;
    fn exchange(
        &mut self,
        version: u32,
        hardware_id: &[u8],
        context: u64,
        message: &[u8],
    ) -> Result<(Vec<u8>, u32)>;
    fn sign(&mut self, context: u64, message: &[u8]) -> Result<Vec<u8>>;
    fn teardown(&mut self, context: u64) -> Result<()>;
    fn close(&mut self) -> Result<()>;
}

pub struct Signer<G: SapGuest> {
    guest: Option<G>,
    context: u64,
    hardware_id: Zeroizing<Vec<u8>>,
}

impl<G: SapGuest> Signer<G> {
    pub fn new<C: SapHttpClient>(
        guest: G,
        protocol: &SapProtocol<C>,
        config: &SapConfig,
        hardware_id: &[u8],
    ) -> Result<Self> {
        let mut signer = Self {
            guest: Some(guest),
            context: 0,
            hardware_id: Zeroizing::new(hardware_id.to_vec()),
        };
        validate_sap_config(config)?;
        if hardware_id.is_empty() || hardware_id.len() > 20 {
            bail!("SAP hardware ID must contain between 1 and 20 bytes");
        }
        signer.context = signer
            .guest
            .as_mut()
            .context("SAP signer is closed")?
            .initialize(&signer.hardware_id)
            .context("initialize Apple SAP session")?;
        if signer.context == 0 {
            bail!("Apple SAP session returned an empty context");
        }
        let certificate = protocol
            .certificate(config.certificate_url.clone())
            .context("fetch SAP certificate")?;
        let context = signer.context;
        let (request, state) = signer
            .guest
            .as_mut()
            .context("SAP signer is closed")?
            .exchange(config.version, &signer.hardware_id, context, &certificate)
            .context("create SAP setup message")?;
        if state != 1 {
            bail!("SAP setup entered unexpected state {state}");
        }
        if request.is_empty() {
            bail!("SAP setup message is empty");
        }
        let reply = protocol
            .exchange(config.setup_url.clone(), &request)
            .context("exchange SAP setup message")?;
        let (_, state) = signer
            .guest
            .as_mut()
            .context("SAP signer is closed")?
            .exchange(config.version, &signer.hardware_id, context, &reply)
            .context("complete SAP setup")?;
        if state != 0 {
            bail!("SAP setup completed in unexpected state {state}");
        }
        Ok(signer)
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let context = self.context;
        if context == 0 {
            bail!("SAP signer is closed");
        }
        let signature = self
            .guest_mut()?
            .sign(context, message)
            .context("sign Apple request")?;
        if signature.is_empty() {
            bail!("sign Apple request: signature is empty");
        }
        Ok(signature)
    }

    pub fn close(&mut self) -> Result<()> {
        self.hardware_id.zeroize();
        let Some(mut guest) = self.guest.take() else {
            return Ok(());
        };
        let teardown = if self.context != 0 {
            guest.teardown(self.context).context("teardown SAP session")
        } else {
            Ok(())
        };
        self.context = 0;
        let close = guest.close().context("close SAP runtime");
        match (teardown, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(first), Err(second)) => Err(first.context(second)),
        }
    }

    fn guest_mut(&mut self) -> Result<&mut G> {
        self.guest.as_mut().context("SAP signer is closed")
    }
}

impl<G: SapGuest> Drop for Signer<G> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use reqwest::Method;
    use url::Url;

    use super::*;
    use crate::sap_protocol::{SapRequest, SapResponse};

    #[derive(Default)]
    struct GuestState {
        exchanges: usize,
        signs: usize,
        teardowns: usize,
        closes: usize,
        wrong_state: bool,
    }

    struct FakeGuest(Rc<RefCell<GuestState>>);

    impl SapGuest for FakeGuest {
        fn initialize(&mut self, hardware_id: &[u8]) -> Result<u64> {
            assert_eq!(hardware_id, [1, 2, 3, 4, 5, 6]);
            Ok(42)
        }

        fn exchange(
            &mut self,
            version: u32,
            hardware_id: &[u8],
            context: u64,
            message: &[u8],
        ) -> Result<(Vec<u8>, u32)> {
            assert_eq!(version, 200);
            assert_eq!(hardware_id, [1, 2, 3, 4, 5, 6]);
            assert_eq!(context, 42);
            let mut state = self.0.borrow_mut();
            state.exchanges += 1;
            if state.exchanges == 1 {
                assert_eq!(message, b"certificate");
                Ok((b"request".to_vec(), if state.wrong_state { 2 } else { 1 }))
            } else {
                assert_eq!(message, b"reply");
                Ok((Vec::new(), 0))
            }
        }

        fn sign(&mut self, context: u64, message: &[u8]) -> Result<Vec<u8>> {
            assert_eq!(context, 42);
            assert_eq!(message, b"payload");
            self.0.borrow_mut().signs += 1;
            Ok(b"signature".to_vec())
        }

        fn teardown(&mut self, context: u64) -> Result<()> {
            assert_eq!(context, 42);
            self.0.borrow_mut().teardowns += 1;
            Ok(())
        }

        fn close(&mut self) -> Result<()> {
            self.0.borrow_mut().closes += 1;
            Ok(())
        }
    }

    struct FakeClient;

    impl SapHttpClient for FakeClient {
        fn send(&self, request: SapRequest) -> Result<SapResponse> {
            let (key, value) = if request.method == Method::GET {
                ("sign-sap-setup-cert", b"certificate".as_slice())
            } else {
                ("sign-sap-setup-buffer", b"reply".as_slice())
            };
            let mut dictionary = plist::Dictionary::new();
            dictionary.insert(key.into(), plist::Value::Data(value.to_vec()));
            let mut body = Vec::new();
            plist::to_writer_xml(&mut body, &plist::Value::Dictionary(dictionary))?;
            Ok(SapResponse { status: 200, body })
        }
    }

    fn config() -> SapConfig {
        SapConfig {
            auth_endpoint: Url::parse(
                "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
            )
            .unwrap(),
            setup_url: Url::parse("https://example.test/setup").unwrap(),
            certificate_url: Url::parse("https://example.test/cert").unwrap(),
            version: 200,
        }
    }

    #[test]
    fn completes_setup_signs_and_closes_once() {
        let state = Rc::new(RefCell::new(GuestState::default()));
        let protocol = SapProtocol::new(FakeClient);
        let mut signer = Signer::new(
            FakeGuest(Rc::clone(&state)),
            &protocol,
            &config(),
            &[1, 2, 3, 4, 5, 6],
        )
        .unwrap();
        assert_eq!(signer.sign(b"payload").unwrap(), b"signature");
        signer.close().unwrap();
        signer.close().unwrap();
        assert!(signer.sign(b"payload").is_err());
        let observed = state.borrow();
        assert_eq!(
            (
                observed.exchanges,
                observed.signs,
                observed.teardowns,
                observed.closes
            ),
            (2, 1, 1, 1)
        );
    }

    #[test]
    fn failed_setup_tears_down_guest() {
        let state = Rc::new(RefCell::new(GuestState {
            wrong_state: true,
            ..Default::default()
        }));
        let protocol = SapProtocol::new(FakeClient);
        let result = Signer::new(
            FakeGuest(Rc::clone(&state)),
            &protocol,
            &config(),
            &[1, 2, 3, 4, 5, 6],
        );
        assert!(result.is_err());
        let observed = state.borrow();
        assert_eq!(
            (observed.exchanges, observed.teardowns, observed.closes),
            (1, 1, 1)
        );
    }
}
