// main.rs (Party)
use openssl::bn::BigNum;
use swallet_rust::party::presign::PresignData;

use std::env;
use std::thread;
use std::time::Duration;

use swallet_rust::common::crypto_utils::print_point;
use swallet_rust::common::params::{get_system_params_mut, init_system_params};
use swallet_rust::party::keygen;
use swallet_rust::party::presign;
use swallet_rust::party::sign;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SilentTS-Lite Party ===");

    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <party ID> [offline flag]", args[0]);
        eprintln!("  party ID: 参与方ID (0-based)");
        eprintln!("  offline flag: 0=在线, 1=离线");
        return Ok(());
    }

    let party_id: usize = match args[1].parse() {
        Ok(id) => id,
        Err(_) => {
            eprintln!("Error: party ID must be a number");
            return Ok(());
        }
    };

    let mut offline_flag = false;
    if args.len() >= 3 {
        offline_flag = match args[2].parse::<i32>() {
            Ok(0) => false,
            Ok(1) => true,
            _ => {
                eprintln!("Error: offline flag must be 0 or 1");
                return Ok(());
            }
        };
    }

    println!("Party ID: {}", party_id);
    println!("Offline mode: {}", offline_flag);

    // Setup
    println!("setup:");

    if !setup(party_id)? {
        println!("setup failed");
        return Ok(());
    }

    let listen_port = {
        // 加载配置
        const CONFIG_FILE: &str = "config.json";
        let mut sys_params = get_system_params_mut();
        sys_params.load_party_config(CONFIG_FILE, party_id as i32)?;
        sys_params.parties[party_id].port as u16
    };

    // Keygen
    println!("keygen:");

    let key_pair = match keygen(listen_port, party_id) {
        Ok(kp) => kp,
        Err(e) => {
            println!("keygen failed: {}", e);
            return Ok(());
        }
    };

    println!();

    // 等待其他参与方
    println!("waiting for parties ...\n");
    thread::sleep(Duration::from_secs(3));

    //presign
    println!("presign:");

    let presigndata = match presign(listen_port, party_id, &key_pair.secret_share) {
        Ok(presigndata) => presigndata,
        Err(e) => {
            println!("presign failed: {}", e);
            return Ok(());
        }
    };

    if offline_flag {
        println!("Offline mode enabled, skipping sign phase.");
        return Ok(());
    }

    //sign
    println!("sign:");

    if let Err(e) = sign(&presigndata, listen_port, party_id) {
        println!("sign failed: {}", e);
        return Ok(());
    }

    println!("Party completed successfully!");
    Ok(())
}

// Setup 函数
fn setup(party_id: usize) -> Result<bool, Box<dyn std::error::Error>> {
    println!("Initializing SilentTS-Lite Party {}...", party_id);

    if !init_system_params().is_ok() {
        eprintln!("Failed to initialize system parameters");
        return Ok(false);
    }

    println!("System parameters initialized successfully");
    Ok(true)
}

// Keygen 阶段
fn keygen(
    listen_port: u16,
    party_id: usize,
) -> Result<keygen::KeyPair, Box<dyn std::error::Error>> {
    // 生成密钥对
    let key_pair = match keygen::generate_key_pair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Failed to generate key pair: {}", e);
            return Err(e);
        }
    };

    // 打印密钥对信息
    print_keypair_info(&key_pair, party_id)?;

    // 运行分布式密钥生成协议
    let final_key_pair = keygen::run_keygen(key_pair, listen_port, party_id)?;
    let vk = &final_key_pair.vk;
    print_point(vk)?;

    Ok(final_key_pair)
}

//presign 阶段
fn presign(
    listen_port: u16,
    party_id: usize,
    secret_share: &BigNum,
) -> Result<PresignData, Box<dyn std::error::Error>> {
    // 运行预签名协议
    let final_presign_data = presign::run_presign(secret_share, listen_port, party_id)?;

    Ok(final_presign_data)
}

//签名阶段
fn sign(
    presign_data: &PresignData,
    listen_port: u16,
    party_id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // 运行签名协议
    sign::run_sign(presign_data, listen_port, party_id)?;

    Ok(())
}

// 打印密钥对信息
fn print_keypair_info(
    key_pair: &keygen::KeyPair,
    party_id: usize,
) -> Result<(), openssl::error::ErrorStack> {
    let params = get_system_params_mut();
    let group = &params.group;
    let mut ctx = openssl::bn::BigNumContext::new()?;

    println!("Key pair generated successfully for party {}:", party_id);

    // 打印私钥
    println!(
        "  Secret share x_{}: {} bits",
        party_id,
        key_pair.secret_share.num_bits()
    );

    // 打印公钥坐标
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    if key_pair
        .public_share
        .affine_coordinates(group, &mut x, &mut y, &mut ctx)
        .is_ok()
    {
        println!("  Public share y_{}:", party_id);
        println!("    x = {}", hex::encode(x.to_vec()));
        println!("    y = {}", hex::encode(y.to_vec()));
    }

    Ok(())
}
