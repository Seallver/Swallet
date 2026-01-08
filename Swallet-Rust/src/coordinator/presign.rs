use crate::common::crypto_utils::{copy_ec_point, h1, random_in_zq_star};
use crate::common::network::{
    deserialize_ec_point, serialize_ec_point, MessageType, NetworkMessage, NetworkService,
};
use crate::common::params::{get_system_params, NUM_PARTIES};
use openssl::bn::BigNumContext;
use openssl::ec::EcPoint;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
// 全局状态
pub struct PresignState {
    pub r: Arc<Mutex<Option<EcPoint>>>,
    pub r_received_count: Arc<Mutex<usize>>,
}

impl PresignState {
    pub fn new() -> Self {
        PresignState {
            r: Arc::new(Mutex::new(None)),
            r_received_count: Arc::new(Mutex::new(0)),
        }
    }
}

// 消息处理器
pub fn create_presign_handler(
    state: Arc<PresignState>,
) -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        presign_message_handler(msg, Arc::clone(&state));
    })
}

fn presign_message_handler(msg: &NetworkMessage, state: Arc<PresignState>) {
    match msg.msg_type {
        MessageType::MsgPublicR => {
            match handle_public_r(msg, &state) {
                Ok(should_stop) => {
                    if should_stop {
                        // 设置退出标志
                        crate::common::network::LISTEN_THREAD_EXIT.store(true, Ordering::SeqCst);
                    }
                }
                Err(e) => {
                    eprintln!("Error handling public R: {:?}", e);
                }
            }
        }
        _ => {
            println!(
                "Received unexpected message type in presign phase: {}",
                msg.msg_type.as_str()
            );
        }
    }
}

fn handle_public_r(
    msg: &NetworkMessage,
    state: &PresignState,
) -> Result<bool, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 反序列化 R_i
    let r_i_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let r_i = deserialize_ec_point(&r_i_hex)?;

    // 更新全局 R
    let mut r_lock = state.r.lock().unwrap();
    let mut count_lock = state.r_received_count.lock().unwrap();

    match &mut *r_lock {
        Some(r) => {
            // 累加 R
            let mut sum = EcPoint::new(group)?;
            sum.add(group, r, &r_i, &mut ctx)?;
            *r = sum;
        }
        None => {
            // 第一个收到的 R_i
            *r_lock = Some(r_i);
        }
    }

    *count_lock += 1;

    // 检查是否收到所有参与方的 R
    if *count_lock >= NUM_PARTIES {
        return Ok(true); // 应该停止监听
    }

    Ok(false) // 继续监听
}

// 发送预签名材料给所有参与方
pub fn send_to_parties(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;
    let h = h1(password.as_bytes())?;

    let params = get_system_params();

    for i in 1..=NUM_PARTIES {
        let alpha = random_in_zq_star()?;
        let gamma_i = {
            let mut point = params.generator.to_owned(group)?;
            let temp = point.to_owned(group)?;
            // 计算 Gamma_i = alpha * G
            point.mul(group, &temp, &alpha, &mut ctx)?;
            point
        };

        let sw_i = {
            let mut point = EcPoint::new(group)?;
            // 计算 sw_i = gamma_i * h
            point.mul(group, &gamma_i, &h, &mut ctx)?;
            point
        };

        // 序列化 - 压缩格式，固定33字节 = 66字符
        let gamma_hex = serialize_ec_point(&gamma_i)?;
        let sw_hex = serialize_ec_point(&sw_i)?;

        // 去除可能的空字符，确保长度正确
        let gamma_hex = gamma_hex.trim_matches('\0');
        let sw_hex = sw_hex.trim_matches('\0');

        println!("[*] Gamma hex: {}...", &gamma_hex);
        println!("[*] SW hex: {}...", &sw_hex);

        // 验证长度
        if gamma_hex.len() != 66 || sw_hex.len() != 66 {
            return Err(format!(
                "Invalid hex length: gamma={}, sw={}, both should be 66",
                gamma_hex.len(),
                sw_hex.len()
            )
            .into());
        }

        // 直接拼接（总长度132字符）
        let data = format!("{}{}", gamma_hex, sw_hex);
        println!(
            "[*] Data length: {} chars, {} bytes",
            data.len(),
            data.as_bytes().len()
        );

        // 获取参与方信息
        let party = &params.parties[i];

        println!(
            "[*] Sending presign data to party {} at {}:{}",
            i, party.ip, party.port
        );

        // 直接发送消息（使用你现有的 send_message 函数）
        crate::common::network::send_message(
            0, // Coordinator ID
            &party.ip,
            party.port as u16,
            MessageType::MsgPresignData,
            data.as_bytes(),
        )?;
    }
    Ok(())
}

// 接收 R 的主函数
pub fn recv_r(port: u16) -> Result<EcPoint, Box<dyn std::error::Error>> {
    let state = Arc::new(PresignState::new());
    let state_clone = Arc::clone(&state);

    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_presign_handler(state_clone);
    network_service.set_message_handler(handler);

    // 重置退出标志
    crate::common::network::LISTEN_THREAD_EXIT.store(false, Ordering::SeqCst);

    // 启动监听线程
    network_service.start_listen_thread(port)?;

    println!("[*] Coordinator started, waiting for public R from parties...");

    // 等待接收所有 R
    loop {
        {
            if crate::common::network::LISTEN_THREAD_EXIT.load(Ordering::SeqCst) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    // 停止网络服务
    network_service.stop();

    // 获取最终的 R
    let r_lock = state.r.lock().unwrap();
    let r_clone = copy_ec_point(r_lock.as_ref().unwrap())?;

    {
        let r_hex = serialize_ec_point(&r_clone)?;
        println!("[+] Final aggregated R: {}", r_hex);
    }

    Ok(r_clone)
}
