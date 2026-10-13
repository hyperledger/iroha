//! Resource observations for the experimental ballot proof; no qualification verdict.

mod qualification;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    qualification::run(
        &std::env::args().skip(1).collect::<Vec<_>>(),
        &mut std::io::stdout().lock(),
    )
}
