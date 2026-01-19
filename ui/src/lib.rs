use slint::ComponentHandle;

mod integration;

slint::include_modules!();

#[derive(Clone, Copy)]
pub struct AppConfig {
    pub initial_mode: NodeMode,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            initial_mode: NodeMode::Client,
        }
    }
}

pub fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    run_app_with_config(AppConfig::default())
}

pub fn run_app_with_config(config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    let ui = MainWindow::new()?;
    let controller = integration::AppController::new(ui.clone_strong(), config);
    controller.bind();

    ui.run()?;

    Ok(())
}

#[no_mangle]
pub extern "C" fn netinfinity_run() {
    if let Err(error) = run_app_with_config(AppConfig::default()) {
        eprintln!("NetInfinity app failed: {error}");
    }
}
