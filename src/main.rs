use std::fs::File;
use std::io::{self, BufRead, Write};
use std::process::Command;
use std::thread;
use clap::{App, Arg};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use url::Url;
use log::{info, error};
use env_logger;

fn main() -> io::Result<()> {
    // Initialize the logger for better logging
    env_logger::init();

    let matches = App::new("TestSSL Wrapper")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .value_name("INPUT")
            .help("Specify input source: 'ip' or 'file'")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("source")
            .short("s")
            .long("source")
            .value_name("SOURCE")
            .help("Specify the IP address, domain, or file containing IPs/domains")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("OUTPUT")
            .help("Specify the output file for testssl results")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("threads")
            .short("t")
            .long("threads")
            .value_name("THREADS")
            .help("Specify the number of threads for concurrent execution")
            .default_value("4")
            .takes_value(true))
        .arg(Arg::with_name("timeout")
            .short("T")
            .long("timeout")
            .value_name("TIMEOUT")
            .help("Specify the timeout in seconds for each testssl scan")
            .default_value("30")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Enable verbose output"))
        .get_matches();

    let input_source = matches.value_of("input").unwrap();
    let source = matches.valueof("source").unwrap();
    let output = matches.valueof("output").unwrap();
    let threads = matches.valueof("threads").unwrap().parse::<usize>().unwrap();
    let timeout = matches.valueof("timeout").unwrap().parse::<u64>().unwrap();
    let verbose = matches.is_present("verbose");

    let ips = match input_source {
        "ip" => vec![source],
        "file" => read_ips_from_file(source)?,
        _ => {
            eprintln!("Invalid input source. Use 'ip' or 'file'.");
            std::process::exit(1);
        }
    };

    let mut threads_handles = vec![];

    for ip in &ips {
        let ip_clone = ip.clone();
        let output_clone = output.to_owned();
        let timeout_clone = timeout;

        let thread = thread::spawn(move || {
            let scan_result = run_testssl(&ip_clone, verbose, timeout_clone);

            let filename = format!("{}/test_ssl-{}", output_clone, ip_clone);
            match File::create(&filename) {
                Ok(mut file) => {
                    if let Err(err) = file.write_all(scan_result.as_bytes()) {
                        error!("Failed to write to file {}: {}", &filename, err);
                    }
                }
                Err(err) => {
                    error!("Failed to create file {}: {}", &filename, err);
                }
            }

            info!("Scan for {} completed.", ip_clone);
        });

        threads_handles.push(thread);
    }

    for handle in threads_handles {
        handle.join().expect("Thread panicked");
    }

    Ok(())
}

fn read_ips_from_file(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let mut ips = Vec::new();

    for line in reader.lines() {
        ips.push(line?);
    }

    Ok(ips)
}

fn run_testssl(target: &str, verbose: bool, timeout: u64) -> String {
    let mut cmd = Command::new("testssl.sh");
    cmd.arg(target);

    if verbose {
        cmd.arg("--verbose");
    }

    cmd.timeout(Duration::from_secs(timeout));

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).to_string()
            } else {
                error!("Failed to run testssl for {}: {}", target, String::from_utf8_lossy(&output.stderr));
                String::new()
            }
        }
        Err(err) => {
            error!("Error running testssl for {}: {}", target, err);
            String::new()
        }
    }
}
