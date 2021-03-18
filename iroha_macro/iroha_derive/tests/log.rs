#[cfg(test)]
mod tests {

    use iroha_derive::log;

    fn init_logger() {
        iroha_logger::init(&iroha_logger::config::LoggerConfiguration {
            max_log_level: log::LevelFilter::Trace,
            terminal_color_enabled: true,
            date_time_format: "%Y-%m-%d %H:%M:%S:%f".to_string(),
        })
        .expect("Failed to initialize logger.");
    }

    #[log]
    fn func_to_log(arg1: String) -> Result<String, String> {
        Ok(arg1)
    }

    #[log("trace")]
    fn func_to_log2(arg1: String, _arg2: String) -> Result<String, String> {
        Ok(arg1)
    }

    /// ```
    /// fn func_after_log(arg1: String) -> Result<String, String> {
    ///     println!("DATE_TIME func_to_log[start]: arg1 = {:?}", arg1);
    ///     let result = Ok(arg1);
    ///     println!("DATE_TIME func_to_log[end]: result = {:?}", result);
    ///     result
    /// }
    /// ```
    #[test]
    fn test_single_argument_function() {
        init_logger();
        let test_value = "test_value".to_string();
        assert_eq!(
            test_value,
            func_to_log(test_value.clone()).expect("Failed to execute function.")
        );
    }

    #[test]
    fn test_two_argument_function() {
        init_logger();
        let test_value = "test_value".to_string();
        assert_eq!(
            test_value,
            func_to_log2(test_value.clone(), "not_used_value".to_string())
                .expect("Failed to execute function.")
        );
    }
}
