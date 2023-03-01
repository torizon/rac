use vergen::{Config, vergen};
use vergen::{ShaKind};

fn main() {
    // Generate the default 'cargo:' instruction output
    let mut config = Config::default();
    *config.git_mut().sha_kind_mut() = ShaKind::Both;
    vergen(config).unwrap();
}
