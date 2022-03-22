use std::time::Duration;

use help1::{create_msg_for_size, read_msg_from_file, sm2::{sm2_encrypt, sm2_generate_key_pair}, sm4::sm4_encrypt, aes::aes_encrypt, rsa::rsa_encrypt};
use log::{LevelFilter, SetLoggerError};
use log4rs::{config::{Appender, Root}, filter::threshold::ThresholdFilter, append::console::{ConsoleAppender, Target}};

fn init() {
    let b = 1;
    let kb = 1024 * b;
    let mb = 1024 * kb;
    create_msg_for_size("256B", 256 * b).unwrap();
    create_msg_for_size("2KB", 2 * kb).unwrap();
    create_msg_for_size("32KB", 32 * kb).unwrap();
    create_msg_for_size("256KB", 256 * kb).unwrap();
    create_msg_for_size("2M", 2 * mb).unwrap();
    create_msg_for_size("16M", 16 * mb).unwrap();
    create_msg_for_size("128M", 128 * mb).unwrap();
}

fn test_benchmark(encrypt: fn(&[u8], &str, &str) -> Duration, sizename: &str) {
    // let mut durations = vec![];
    let mut total_duration = Duration::new(0, 0);
    for i in 0..10 {
        let ref filename = format!("{}.txt", i);
        let plain_text = read_msg_from_file(sizename, filename).unwrap();
        let duration = encrypt(&plain_text, sizename, filename);
        total_duration += duration;
        // durations.push(duration);
    }
    let duration_millis = total_duration.as_secs_f64();
    let avg_duration_f64 = duration_millis / 10_f64;
    let avg_duration = Duration::from_secs_f64(avg_duration_f64);
    log::info!("average duration: {:.2?}", avg_duration);
}

fn init_log() -> Result<(), SetLoggerError> {
    use log4rs::{append::file::FileAppender, encode::pattern::PatternEncoder, Config};

    let level = log::LevelFilter::Info;
    let stderr = ConsoleAppender::builder()
        .target(Target::Stderr).build();

    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {m}{n}")))
        .build("bar.log").unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(LevelFilter::Trace),
        )
        .unwrap();
    let _handle = log4rs::init_config(config)?;
    Ok(())
}


fn main() {
    init_log().unwrap();
    init();
    // let _sizenames = ["256B", "2KB", "32KB", "256KB", "2M", "16M", "128M"];
    // let sizenames = ["256B", "2KB", "32KB", "256KB", "2M", "16M"];
    let sizenames = ["128M"];

    for sizename in sizenames {
        test_benchmark(rsa_encrypt, sizename);
    }

    for sizename in sizenames {
        test_benchmark(aes_encrypt, sizename);
    }

    for sizename in sizenames {
        test_benchmark(sm4_encrypt, sizename);
    }

    // sm2_generate_key_pair().unwrap();
    // for sizename in sizenames {
    //     test_benchmark(sm2_encrypt, sizename);
    // }

    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use help1::rsa::rsa_encrypt;

    use super::*;

    #[test]
    fn sm2_test() {
        let sizename = "256B";

        let mut durations = vec![];
        let mut total_duration = Duration::new(0, 0);
        for i in 0..10 {
            let ref filename = format!("{}.txt", i);
            let plain_text = read_msg_from_file(sizename, filename).unwrap();
            let duration = sm2_encrypt(&plain_text, sizename, filename);
            total_duration += duration;
            durations.push(duration);
        }
        let duration_millis = total_duration.as_secs_f64();
        let avg_duration_f64 = duration_millis / (durations.len() as f64);
        let avg_duration = Duration::from_secs_f64(avg_duration_f64);
        log::info!("average duration: {:.2?}", avg_duration);
    }

    #[test]
    fn rsa_test() {
        let sizename = "256B";
        let mut durations = vec![];
        let mut total_duration = Duration::new(0, 0);
        for i in 0..10 {
            let ref filename = format!("{}.txt", i);
            let plain_text = read_msg_from_file(sizename, filename).unwrap();
            let duration = rsa_encrypt(&plain_text, sizename, filename);
            total_duration += duration;
            durations.push(duration);
        }
        let duration_millis = total_duration.as_secs_f64();
        let avg_duration_f64 = duration_millis / (durations.len() as f64);
        let avg_duration = Duration::from_secs_f64(avg_duration_f64);
        log::info!("average duration: {:.2?}", avg_duration);
        // println!("average duration: {:.2?}", avg_duration);
    }
}