use super::*;

#[derive(ClapArgs, Debug, Clone, Copy)]
pub struct Args;

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let schemas = iroha_schema_gen::build_schemas();
        writeln!(writer, "{}", serde_json::to_string_pretty(&schemas)?)
            .wrap_err("Failed to write schema.")
    }
}
