use std::net::{Ipv4Addr, TcpStream};
use std::{env, fs, thread};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use winfw::{new_fw_rule, Actions, FwRule, Protocols};

const ANTIVIRUS_PATHS: [&str; 4] = [
    "C:\\Program Files\\Kaspersky Lab\\Kaspersky Anti-Virus",
    "C:\\Program Files\\Doctor Web",
    "C:\\Program Files\\Kaspersky Lab\\Kaspersky Internet Security",
    "C:\\Program Files\\AVAST Software\\Avast",
];
const FIREWALL_PATH: &str = "C:\\Windows\\System32\\WF.msc";
const PING_ADDR: &str = "8.8.8.8";
const BAD_PAYLOAD_FOR_ANTIVIRUS: &str = r#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H"+"+H*"#;
const BAD_FILE_NAME: &str = "data_for_check_antivirus.txt";
const IP_FOR_TESTING_BLOCK: &str = "64.233.164.138";

fn main() {
    print_menu();
    let mut secutiry_check_results = SecurityCheckResults::new();
    let mut command = String::new();
    loop {
        print_prompt();
        io::stdin().read_line(&mut command).unwrap();
        match command.as_str().trim() {
            "0" => {
                println!("{}", secutiry_check_results.to_string());
                break;
            },
            "1" => secutiry_check_results.set_internet_result(is_internet_works()),
            "2" => secutiry_check_results
                .set_installed_result(are_antivirus_and_firewall_is_installed()),
            "3" => secutiry_check_results.set_firewall_check_result(is_firewall_works()),
            "4" => secutiry_check_results.set_antivirus_check_result(is_antivirus_works()),
            &_ => println!("Неизвестная команда!"),
        }
        command.clear();
    }
}

fn print_prompt() {
    print!("> ");
    io::stdout().flush().expect("Failed to flush stdout");
}

fn print_menu() {
    println!("----------------SECURITY CHECK----------------");
    println!("Действия: ");
    println!("0. Выход");
    println!("1. Проверить интернет");
    println!("2. Проверить, установлен ли МСЭ и антивирус");
    println!("3. Проверить работоспособность МСЭ");
    println!("4. Проверить работоспособность антивируса");
}

fn is_firewall_works() -> bool {
    let mut new_test_rule = FwRule::default();
    new_test_rule.name = "TEST".to_string();
    new_test_rule.description = "Rule for test firewall work".to_string();
    new_test_rule.grouping = "Test Rule Group".to_string();
    new_test_rule.action = Actions::Block;
    new_test_rule.enabled = true;
    new_test_rule.protocol = Protocols::Any;
    new_test_rule.remote_addresses = IP_FOR_TESTING_BLOCK.to_string();
    match new_fw_rule(&new_test_rule) {
        Err(e) => {
            println!("Can't create test rule: {}", e);
            false
        },
        Ok(()) => {
            let port = 443;
            let timeout = Duration::from_secs(2);
            let ip: Ipv4Addr = Ipv4Addr::new(64, 233, 164, 138).into();
            match TcpStream::connect_timeout(&format!("{:?}:{}", ip, port).parse().unwrap(), timeout) {
                Ok(_) => false,
                Err(_) => true
            }
        } 
    }
}

fn are_antivirus_and_firewall_is_installed() -> bool {
    let mut antivirus_is_installed = false;
    let mut firewall_is_installed = false;
    // Check if antivirus installed
    for path in ANTIVIRUS_PATHS {
        let path = Path::new(path);
        if path.exists() {
            antivirus_is_installed = true
        }
    }
    // Check if firewall installed
    let firewall_path = Path::new(FIREWALL_PATH);
    if firewall_path.exists() {
        firewall_is_installed = true
    }
    antivirus_is_installed & firewall_is_installed
}

fn is_internet_works() -> bool {
    let addr = PING_ADDR.parse().unwrap();
    let data = [1, 2, 3, 4];
    let timeout = Duration::from_secs(1);
    let options = ping_rs::PingOptions {
        ttl: 128,
        dont_fragment: true,
    };
    let result = ping_rs::send_ping(&addr, timeout, &data, Some(&options));
    match result {
        Ok(_reply) => true,
        Err(_e) => false,
    }
}

fn is_antivirus_works() -> bool {
    let temp_dir = env::temp_dir();
    let bad_file_path = temp_dir.join(BAD_FILE_NAME);
    let changed_data = BAD_PAYLOAD_FOR_ANTIVIRUS.replace("\"+\"", "");
    match fs::write(&bad_file_path, changed_data) {
        Ok(_) => {
            thread::sleep(Duration::from_secs(10));
            if bad_file_path.exists() {
                false
            } else {
                true
            }
        }
        Err(_) => false
    }
}

#[derive(Default)]
struct SecurityCheckResults {
    internet: Option<bool>,
    firewall_and_antivirus_installed: Option<bool>,
    firewall: Option<bool>,
    antivirus: Option<bool>,
}

impl SecurityCheckResults {
    fn bool_to_string(b: bool) -> &'static str {
        if b { "ДА" } else { "НЕТ" }
    }

    pub fn to_string(&self) -> String {
        let mut result_string = String::new();
        if let Some(internet) = self.internet {
            result_string += format!("{:40}{}", "Есть интернет: ", Self::bool_to_string(internet)).as_str();
            result_string += "\n";
        } 
        if let Some(installed) = self.firewall_and_antivirus_installed {
            result_string += format!("{:40}{}", "МСЭ и антивирус установлены: ", Self::bool_to_string(installed)).as_str();
            result_string += "\n";
        }
        
        if let Some(firewall) = self.firewall {
            result_string += format!("{:40}{}", "Фаервол работает: ", Self::bool_to_string(firewall)).as_str();
            result_string += "\n";
        }
        if let Some(antivirus) = self.antivirus {
            result_string += format!("{:40}{}", "Антивирус работает: ", Self::bool_to_string(antivirus)).as_str();
            result_string += "\n";
        }
        result_string
    }
    
    pub fn new() -> SecurityCheckResults {
        SecurityCheckResults::default()
    }

    pub fn set_internet_result(&mut self, result: bool) {
        self.internet = Some(result);
    }

    pub fn set_installed_result(&mut self, result: bool) {
        self.firewall_and_antivirus_installed = Some(result)
    }

    pub fn set_firewall_check_result(&mut self, result: bool) {
        self.firewall = Some(result)
    }

    pub fn set_antivirus_check_result(&mut self, result: bool) {
        self.antivirus = Some(result)
    }

}
