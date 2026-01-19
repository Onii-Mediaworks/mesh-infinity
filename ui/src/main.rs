fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();
    net_infinity_ui::run_app_with_config(config)
}

fn parse_args() -> net_infinity_ui::AppConfig {
    let mut mode = net_infinity_ui::NodeMode::Client;
    let mut args = std::env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                if let Some(value) = args.next() {
                    if let Some(parsed) = parse_mode(&value) {
                        mode = parsed;
                    }
                }
            }
            "--client" => mode = net_infinity_ui::NodeMode::Client,
            "--server" => mode = net_infinity_ui::NodeMode::Dual,
            "--dual" => mode = net_infinity_ui::NodeMode::Dual,
            "--server-only" => mode = net_infinity_ui::NodeMode::Server,
            _ => {
                if let Some(value) = arg.strip_prefix("--mode=") {
                    if let Some(parsed) = parse_mode(value) {
                        mode = parsed;
                    }
                }
            }
        }
    }

    net_infinity_ui::AppConfig {
        initial_mode: mode,
    }
}

fn parse_mode(value: &str) -> Option<net_infinity_ui::NodeMode> {
    match value.to_ascii_lowercase().as_str() {
        "client" => Some(net_infinity_ui::NodeMode::Client),
        "server" => Some(net_infinity_ui::NodeMode::Server),
        "dual" => Some(net_infinity_ui::NodeMode::Dual),
        _ => None,
    }
}
