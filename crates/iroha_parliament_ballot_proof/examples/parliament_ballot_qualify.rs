//! Resource observations for the experimental ballot proof; no qualification verdict.

mod qualification;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mut output = std::io::stdout().lock();
    qualification::run(&arguments, &mut output)
}
