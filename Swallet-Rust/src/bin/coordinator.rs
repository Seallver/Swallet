// main.rs 或 coordinator.rs
use openssl::ec::EcPoint;
use std::thread;
use std::time::Duration;
use swallet_rust::common;

use swallet_rust::common::crypto_utils::print_point;
use swallet_rust::common::params::{get_system_params_mut, init_system_params};
use swallet_rust::coordinator::keygen;
use swallet_rust::coordinator::presign;
use swallet_rust::coordinator::sign;

// 全局常量
const CONFIG_FILE: &str = "config.json";
// const MESSAGE: &[u8] = b"message to sign";

// 主函数
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SilentTS-Lite Coordinator ===");

    // Setup
    println!("setup:");

    if !setup()? {
        println!("setup failed");
        return Ok(());
    }

    // 加载配置
    let port = {
        let mut sys_params = get_system_params_mut();
        sys_params.load_party_config(CONFIG_FILE, 0)?;
        // 提前提取需要的数据
        sys_params.parties[0].port
    };

    // Keygen
    println!("keygen:");

    let vk = match keygen(port) {
        Ok(vk) => vk,
        Err(e) => {
            println!("keygen failed: {}", e);
            return Ok(());
        }
    };
    // 打印 VK
    print_point(&vk)?;

    println!();

    // 等待参与方
    println!("waiting for parties ...\n");
    thread::sleep(Duration::from_secs(4));

    //presign
    println!("presign:");

    let r = match presign(port) {
        Ok(r) => r,
        Err(e) => {
            println!("presign failed: {}", e);
            return Ok(());
        }
    };
    // 打印 R
    print_point(&r)?;

    //sign
    println!("sign:");

    if let Err(e) = sign(&r, &vk, port, 0) {
        println!("sign failed: {}", e);
        return Ok(());
    }

    println!("Coordinator completed successfully!");
    Ok(())
}

// Setup 函数
fn setup() -> Result<bool, Box<dyn std::error::Error>> {
    println!("Initializing SilentTS-Lite Coordinator...");

    if !init_system_params().is_ok() {
        eprintln!("Failed to initialize system parameters");
        return Ok(false);
    }

    println!("System parameters initialized successfully");
    Ok(true)
}

// Keygen 阶段
fn keygen(port: u16) -> Result<EcPoint, Box<dyn std::error::Error>> {
    // 运行协调器密钥生成

    let vk = keygen::recv_vk(port)?;

    Ok(vk)
}

// presign 阶段
pub fn presign(port: u16) -> Result<EcPoint, Box<dyn std::error::Error>> {
    let password = common::params::PASSWORD;

    // 1. 发送预签名材料给所有参与方
    presign::send_to_parties(password)?;
    println!("[+] Presign data sent to all parties");

    // 2. 接收所有参与方的 R_i 并计算最终的 R
    let r = presign::recv_r(port)?;

    Ok(r)
}

//sign 阶段
pub fn sign(
    r_point: &EcPoint,
    vk: &EcPoint,
    listen_port: u16,
    party_id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // 运行签名协议
    sign::run_sign(r_point, vk, listen_port, party_id)?;

    Ok(())
}
