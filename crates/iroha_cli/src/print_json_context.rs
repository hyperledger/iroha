struct PrintJsonContext<W, E> {
    write: W,
    err_write: E,
    config: Config,
    filesystem_config: client_config::FilesystemConfig,
    /// The configuration is the offline sentinel used by configuration-free helpers.
    offline_fallback: bool,
    operator_key_pair: Option<KeyPair>,
    transaction_metadata: Option<Metadata>,
    fee_payment: FeePaymentArgs,
    input_instructions: bool,
    output_instructions: bool,
    output_format: CliOutputFormat,
    /// Render JSON as compact newline-delimited values (`--output-format jsonl`).
    json_lines: bool,
    i18n: Localizer,
}
impl<W: std::io::Write, E: std::io::Write> RunContext for PrintJsonContext<W, E> {
    fn config(&self) -> &Config {
        &self.config
    }
    fn sccp_config(&self) -> Result<iroha_sccp_wallet::config::SccpClientConfig> {
        self.filesystem_config
            .sccp
            .clone()
            .ok_or_else(|| eyre!("this context has no original SCCP client configuration"))
    }
    fn has_client_config(&self) -> bool {
        !self.offline_fallback
    }
    fn connect_queue_root(&self) -> PathBuf {
        self.filesystem_config.connect_queue_root.clone()
    }
    fn soracloud_http_witness_file(&self) -> Option<&Path> {
        self.filesystem_config
            .soracloud_http_witness_file
            .as_deref()
    }
    fn operator_key_pair(&self) -> Option<&KeyPair> {
        self.operator_key_pair.as_ref()
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        self.transaction_metadata.as_ref()
    }
    fn transaction_fee_payment(&self) -> Result<FeePaymentIntent> {
        self.fee_payment.selection()
    }
    fn input_instructions(&self) -> bool {
        self.input_instructions
    }
    fn output_instructions(&self) -> bool {
        self.output_instructions
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn output_format(&self) -> CliOutputFormat {
        self.output_format
    }
    fn json_lines(&self) -> bool {
        self.json_lines
    }
    /// Serialize and print data
    ///
    /// # Errors
    ///
    /// - if serialization fails
    /// - if printing fails
    fn print_data<T>(&mut self, data: &T) -> Result<()>
    where
        T: JsonSerialize + ?Sized,
    {
        let rendered = render_json_output(data, self.json_lines)?;
        self.write.write_all(rendered.as_bytes())?;
        Ok(())
    }
    fn println(&mut self, data: impl Display) -> Result<()> {
        if self.output_format == CliOutputFormat::Json {
            writeln!(&mut self.err_write, "{data}")?;
        } else {
            writeln!(&mut self.write, "{data}")?;
        }
        Ok(())
    }
    fn println_data(&mut self, data: impl Display) -> Result<()> {
        writeln!(&mut self.write, "{data}")?;
        Ok(())
    }
}
