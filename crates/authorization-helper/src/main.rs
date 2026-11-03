fn main() {
    // There are no command, source-path or destination-path arguments.
    if std::env::args_os().len() != 1 || ipatool_authorization::run_helper().is_err() {
        eprintln!("Authorization helper could not start.");
        std::process::exit(1);
    }
}
