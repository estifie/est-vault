//! est-vault standalone binary.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    let args: Vec<String> = args.into_iter().filter(|a| a != "--json").collect();
    std::process::exit(est_vault::cli::dispatch(&args[1..], json));
}
