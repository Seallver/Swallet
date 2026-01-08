// party_presign.rs
use crate::common::crypto_utils::{copy_bn_option, copy_ec_point_option, random_in_zq_star};
use crate::common::network::{
    broadcast, deserialize_bn, deserialize_ec_point, send_message, serialize_bn,
    serialize_ec_point, MessageType, NetworkMessage, NetworkService,
};
use crate::common::params::{get_system_params, NUM_PARTIES};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// 预签名数据结构
pub struct PresignData {
    pub gamma: Option<EcPoint>,  // Γ = g^{a}
    pub sw: Option<EcPoint>,     // sw = Γ^h
    pub k: Option<BigNum>,       // 临时私钥 k
    pub phi: Option<BigNum>,     // 随机数 phi
    pub x: Option<BigNum>,       // 私钥份额 x
    pub r: Option<EcPoint>,      // R = g^{k}
    pub sum_r: Option<EcPoint>,  // 多方R聚合
    pub big_r: Option<BigNum>,   // r (标量)
    pub u: Option<BigNum>,       // 预签名材料 u
    pub v: Option<BigNum>,       // 预签名材料 v
    pub pre_u: Option<BigNum>,   // 上一个参与方的u
    pub pre_phi: Option<BigNum>, // 上一个参与方的phi
    pub pre_v: Option<BigNum>,   // 上一个参与方的v
}

impl PresignData {
    pub fn new() -> Self {
        PresignData {
            gamma: None,
            sw: None,
            k: None,
            phi: None,
            x: None,
            r: None,
            sum_r: None,
            big_r: None,
            u: None,
            v: None,
            pre_u: None,
            pre_phi: None,
            pre_v: None,
        }
    }

    pub fn init_with_params(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let params = get_system_params();
        let group = &params.group;

        self.gamma = Some(EcPoint::new(group)?);
        self.sw = Some(EcPoint::new(group)?);
        self.r = Some(EcPoint::new(group)?);
        self.sum_r = None;

        self.k = Some(BigNum::new()?);
        self.phi = Some(BigNum::new()?);
        self.x = Some(BigNum::new()?);
        self.big_r = Some(BigNum::new()?);
        self.u = Some(BigNum::new()?);
        self.v = Some(BigNum::new()?);
        self.pre_u = Some(BigNum::new()?);
        self.pre_phi = Some(BigNum::new()?);
        self.pre_v = Some(BigNum::new()?);

        Ok(())
    }
}

// 接收数据结构
pub struct RecvData {
    pub gamma: Option<EcPoint>,  // 接收到的 Gamma
    pub sw: Option<EcPoint>,     // 接收到的 sw
    pub pre_k: Option<BigNum>,   // 上一个参与方的 k
    pub pre_phi: Option<BigNum>, // 上一个参与方的 phi
    pub pre_x: Option<BigNum>,   // 上一个参与方的 x
    pub pre_u: Option<BigNum>,   // 上一个参与方的 u
    pub pre_v: Option<BigNum>,   // 上一个参与方的 v
    pub received: bool,          // 是否接收到数据
    pub r_received_count: usize, // 收到的 R 计数
}

impl RecvData {
    pub fn new() -> Self {
        RecvData {
            gamma: None,
            sw: None,
            pre_k: None,
            pre_phi: None,
            pre_x: None,
            pre_u: None,
            pre_v: None,
            received: false,
            r_received_count: 0,
        }
    }

    pub fn init_with_params(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let params = get_system_params();
        let group = &params.group;

        self.gamma = Some(EcPoint::new(group)?);
        self.sw = Some(EcPoint::new(group)?);
        self.pre_k = Some(BigNum::new()?);
        self.pre_phi = Some(BigNum::new()?);
        self.pre_x = Some(BigNum::new()?);
        self.pre_u = Some(BigNum::new()?);
        self.pre_v = Some(BigNum::new()?);

        Ok(())
    }
}

// 全局状态
pub struct PartyPresignState {
    pub presign_data: Arc<Mutex<PresignData>>,
    pub recv_data: Arc<Mutex<RecvData>>,
    pub is_ready: Arc<Mutex<bool>>,
}

impl PartyPresignState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut presign_data = PresignData::new();
        presign_data.init_with_params()?;

        let mut recv_data = RecvData::new();
        recv_data.init_with_params()?;

        Ok(PartyPresignState {
            presign_data: Arc::new(Mutex::new(presign_data)),
            recv_data: Arc::new(Mutex::new(recv_data)),
            is_ready: Arc::new(Mutex::new(false)),
        })
    }
}

// 消息处理器创建函数
pub fn create_presign_handler(
    state: Arc<PartyPresignState>,
) -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        presign_message_handler(msg, Arc::clone(&state));
    })
}

fn presign_message_handler(msg: &NetworkMessage, state: Arc<PartyPresignState>) {
    match msg.msg_type {
        MessageType::MsgPresignData => match handle_presign_data(msg, &state) {
            Ok(_) => loop {
                let mut is_ready = state.is_ready.lock().unwrap();
                if *is_ready == false {
                    *is_ready = true;
                    break;
                }
            },
            Err(e) => {
                eprintln!("Error handling presign data: {:?}", e);
            }
        },
        MessageType::MsgKeyExchange => match handle_key_exchange(msg, &state) {
            Ok(_) => loop {
                let mut is_ready = state.is_ready.lock().unwrap();
                if *is_ready == false {
                    *is_ready = true;
                    break;
                }
            },
            Err(e) => {
                eprintln!("Error handling key exchange: {:?}", e);
            }
        },
        MessageType::MsgUvData => match handle_uv_data(msg, &state) {
            Ok(_) => loop {
                let mut is_ready = state.is_ready.lock().unwrap();
                if *is_ready == false {
                    *is_ready = true;
                    break;
                }
            },
            Err(e) => {
                eprintln!("Error handling UV data: {:?}", e);
            }
        },
        MessageType::MsgPublicR => match handle_public_r(msg, &state) {
            Ok(should_stop) => {
                if should_stop {
                    // 设置退出标志
                    crate::common::network::LISTEN_THREAD_EXIT.store(true, Ordering::SeqCst);
                }
            }
            Err(e) => {
                eprintln!("Error handling public R: {:?}", e);
            }
        },
        _ => {
            println!(
                "Received unexpected message type in presign phase: {}",
                msg.msg_type.as_str()
            );
        }
    }
}

fn handle_presign_data(
    msg: &NetworkMessage,
    state: &PartyPresignState,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[*] Received presign data, length: {} bytes",
        msg.data.len()
    );

    // 压缩 EC 点：33字节 = 66十六进制字符
    const COMPRESSED_EC_POINT_HEX_LEN: usize = 66;
    const TOTAL_EXPECTED_LEN: usize = COMPRESSED_EC_POINT_HEX_LEN * 2; // 132

    let data_str = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    println!("[*] Data string length: {} chars", data_str.len());
    println!("[*] Expected length: {} chars", TOTAL_EXPECTED_LEN);

    // 验证长度
    if data_str.len() != TOTAL_EXPECTED_LEN {
        return Err(format!(
            "Invalid data length: got {}, expected {} (2 compressed EC points)",
            data_str.len(),
            TOTAL_EXPECTED_LEN
        )
        .into());
    }

    // 分割：前66字符是 Gamma，后66字符是 SW
    let gamma_hex = &data_str[0..COMPRESSED_EC_POINT_HEX_LEN];
    let sw_hex = &data_str[COMPRESSED_EC_POINT_HEX_LEN..TOTAL_EXPECTED_LEN];

    println!("[*] Gamma hex: {}...", &gamma_hex);
    println!("[*] SW hex: {}...", &sw_hex);

    // 验证 hex 格式
    if !gamma_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Gamma hex contains non-hex characters".into());
    }
    if !sw_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("SW hex contains non-hex characters".into());
    }

    // 反序列化
    let gamma = deserialize_ec_point(gamma_hex).map_err(|e| {
        format!(
            "Failed to deserialize Gamma '{}...': {}",
            &gamma_hex[0..8],
            e
        )
    })?;

    let sw = deserialize_ec_point(sw_hex)
        .map_err(|e| format!("Failed to deserialize SW '{}...': {}", &sw_hex[0..8], e))?;

    // 更新状态
    let mut recv_lock = state.recv_data.lock().unwrap();
    let mut presign_lock = state.presign_data.lock().unwrap();

    let params = get_system_params();
    let group = &params.group;

    recv_lock.gamma = Some(gamma.to_owned(group)?);
    recv_lock.sw = Some(sw.to_owned(group)?);
    recv_lock.received = true;

    presign_lock.gamma = Some(gamma);
    presign_lock.sw = Some(sw);

    println!("[+] Successfully processed coordinator presign data");

    Ok(())
}

fn handle_key_exchange(
    msg: &NetworkMessage,
    state: &PartyPresignState,
) -> Result<(), Box<dyn std::error::Error>> {
    if msg.data.len() < 192 {
        return Err("Invalid message data length".into());
    }

    // 将数据直接转换为字节数组切片
    let k_bytes = &msg.data[..32];
    let phi_bytes = &msg.data[32..64];
    let x_bytes = &msg.data[64..96];

    // 创建固定大小的数组
    let mut k_array = [0u8; 32];
    let mut phi_array = [0u8; 32];
    let mut x_array = [0u8; 32];

    k_array.copy_from_slice(k_bytes);
    phi_array.copy_from_slice(phi_bytes);
    x_array.copy_from_slice(x_bytes);

    // 调用 deserialize_bn
    let k = deserialize_bn(&k_array)?;
    let phi = deserialize_bn(&phi_array)?;
    let x = deserialize_bn(&x_array)?;

    let mut recv_lock = state.recv_data.lock().unwrap();

    recv_lock.pre_k = Some(k);
    recv_lock.pre_phi = Some(phi);
    recv_lock.pre_x = Some(x);
    recv_lock.received = true;

    Ok(())
}

fn handle_uv_data(
    msg: &NetworkMessage,
    state: &PartyPresignState,
) -> Result<(), Box<dyn std::error::Error>> {
    if msg.data.len() < 64 {
        return Err("Invalid message data length".into());
    }

    // 将数据直接转换为字节数组切片
    let u_bytes = &msg.data[..32];
    let v_bytes = &msg.data[32..64];

    // 创建固定大小的数组
    let mut u_array = [0u8; 32];
    let mut v_array = [0u8; 32];

    u_array.copy_from_slice(u_bytes);
    v_array.copy_from_slice(v_bytes);

    // 调用 deserialize_bn
    let u = deserialize_bn(&u_array)?;
    let v = deserialize_bn(&v_array)?;

    let mut recv_lock = state.recv_data.lock().unwrap();

    recv_lock.pre_u = Some(u);
    recv_lock.pre_v = Some(v);
    recv_lock.received = true;

    Ok(())
}

fn handle_public_r(
    msg: &NetworkMessage,
    state: &PartyPresignState,
) -> Result<bool, Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    let r_i_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();
    let r_i = deserialize_ec_point(&r_i_hex)?;

    let mut presign_lock = state.presign_data.lock().unwrap();
    let mut recv_lock = state.recv_data.lock().unwrap();

    // 累加 R
    if let Some(ref mut sum_r) = presign_lock.sum_r {
        // 如果已经有值，累加
        let mut new_sum = EcPoint::new(group)?;
        new_sum.add(group, sum_r, &r_i, &mut ctx)?;
        *sum_r = new_sum;
    } else {
        // 如果是 None，直接设置为 r_i
        presign_lock.sum_r = Some(r_i.to_owned(group)?);
    }

    recv_lock.r_received_count += 1;

    // 检查是否收到所有参与方的 R
    if recv_lock.r_received_count >= crate::common::params::NUM_PARTIES {
        // 打印最终的R
        {
            let r_hex = serialize_ec_point(&presign_lock.sum_r.as_ref().unwrap())?;
            println!("[+] Final aggregated R: {}", r_hex);
        }
        return Ok(true); // 应该停止监听
    }

    Ok(false) // 继续监听
}

// 发送 k, phi, x 给下一个参与方
pub fn send_k_phi_x(
    state: &PartyPresignState,
    secret_share: &BigNum,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let my_id = params.current_party_id as usize;

    // 获取下一个参与方的 ID（环状结构）
    let next_id = if my_id == NUM_PARTIES { 1 } else { my_id + 1 };
    let party = &params.parties[next_id];

    let presign_lock = state.presign_data.lock().unwrap();

    // 确保 k, phi 已生成
    let k = presign_lock.k.as_ref().ok_or("k not generated")?;
    let phi = presign_lock.phi.as_ref().ok_or("phi not generated")?;

    // 序列化数据
    let mut buffer = [0u8; 96];
    let k_hex = serialize_bn(k);
    let phi_hex = serialize_bn(phi);
    let x_hex = serialize_bn(secret_share);

    buffer[..k_hex.len()].copy_from_slice(&k_hex);
    buffer[32..32 + phi_hex.len()].copy_from_slice(&phi_hex);
    buffer[64..64 + x_hex.len()].copy_from_slice(&x_hex);

    // 发送消息
    send_message(
        my_id as i32,
        &party.ip,
        party.port as u16,
        MessageType::MsgKeyExchange,
        &buffer.to_vec(),
    )?;

    println!("[*] Sent k, phi, x to party {}", next_id);

    Ok(())
}

// 生成 k 和 phi
pub fn generate_k_phi(state: &PartyPresignState) -> Result<(), Box<dyn std::error::Error>> {
    let mut presign_lock = state.presign_data.lock().unwrap();

    // 随机生成 k 和 phi
    presign_lock.k = Some(random_in_zq_star()?);
    presign_lock.phi = Some(random_in_zq_star()?);

    println!("[+] Generated k and phi");

    Ok(())
}

// 计算 R 并广播
pub fn public_r(state: &PartyPresignState) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    let mut presign_lock = state.presign_data.lock().unwrap();

    // 获取 k
    let k = presign_lock.k.as_ref().ok_or("k not generated")?;

    // 计算 R = g^{k}
    let mut r = EcPoint::new(group)?;
    let generator = &params.generator;
    r.mul(group, generator, k, &mut ctx)?;

    presign_lock.r = Some(r.to_owned(group)?);

    if presign_lock.sum_r.is_none() {
        // 如果是 None，直接设置为 r
        presign_lock.sum_r = Some(r.to_owned(group)?);
    } else {
        // 如果不是 None，执行累加操作
        if let Some(ref mut sum_r) = presign_lock.sum_r {
            let mut new_sum = EcPoint::new(group)?;
            new_sum.add(group, sum_r, &r, &mut ctx)?;
            *sum_r = new_sum;
        }
    }
    let mut recv_lock = state.recv_data.lock().unwrap();
    recv_lock.r_received_count += 1;

    // 检查是否收到所有参与方的 R
    if recv_lock.r_received_count >= crate::common::params::NUM_PARTIES {
        // 打印最终的R
        {
            let r_hex = serialize_ec_point(&presign_lock.sum_r.as_ref().unwrap())?;
            println!("[+] Final aggregated R: {}", r_hex);
        }
        crate::common::network::LISTEN_THREAD_EXIT.store(true, Ordering::SeqCst);
    }

    // 序列化 R 并广播
    let r_hex = serialize_ec_point(&r)?;
    broadcast(MessageType::MsgPublicR, r_hex.as_bytes())?;

    println!("[+] Computed and broadcasted R");

    Ok(())
}

// 计算 u 和 v
pub fn compute_u_v(
    state: &PartyPresignState,
    secret_share: &BigNum,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let q = &params.order;
    let mut ctx = BigNumContext::new()?;

    // 发送 k, phi, x
    send_k_phi_x(state, secret_share)?;

    // 等待接收上一个参与方的数据
    wait_for_received(state)?;

    let mut presign_lock = state.presign_data.lock().unwrap();
    let recv_lock = state.recv_data.lock().unwrap();

    // 获取本地数据
    let k = presign_lock.k.as_ref().ok_or("k not generated")?;
    let phi = presign_lock.phi.as_ref().ok_or("phi not generated")?;
    let x = secret_share;

    // 获取接收到的数据
    let pre_k = recv_lock.pre_k.as_ref().ok_or("pre_k not received")?;
    let pre_phi = recv_lock.pre_phi.as_ref().ok_or("pre_phi not received")?;
    let pre_x = recv_lock.pre_x.as_ref().ok_or("pre_x not received")?;

    // 计算 u
    let mut u = BigNum::new()?;

    // u = k * phi mod q
    u.mod_mul(k, phi, q, &mut ctx)?;

    // u += k * pre_phi mod q
    let mut temp = BigNum::new()?;
    temp.mod_mul(k, pre_phi, q, &mut ctx)?;

    // 方法：先计算和，再赋值
    let mut sum_u = BigNum::new()?;
    sum_u.mod_add(&u, &temp, q, &mut ctx)?;
    u = sum_u; // 赋值回去

    // u += pre_k * phi mod q
    let mut sum_u = BigNum::new()?;
    temp.mod_mul(pre_k, phi, q, &mut ctx)?;

    sum_u.mod_add(&u, &temp, q, &mut ctx)?;
    u = sum_u;

    // 计算 v
    let mut v = BigNum::new()?;

    // v = x * phi mod q
    v.mod_mul(x, phi, q, &mut ctx)?;

    // v += x * pre_phi mod q
    temp.mod_mul(x, pre_phi, q, &mut ctx)?;

    let mut sum_v = BigNum::new()?;
    sum_v.mod_add(&v, &temp, q, &mut ctx)?;
    v = sum_v;

    // v += pre_x * phi mod q
    temp.mod_mul(pre_x, phi, q, &mut ctx)?;

    let mut sum_v = BigNum::new()?;
    sum_v.mod_add(&v, &temp, q, &mut ctx)?;
    v = sum_v;

    // 输出 u 和 v 的值（十六进制）
    println!("[+] Computed u and v:");
    println!("  u = {}", u.to_hex_str()?);
    println!("  v = {}", v.to_hex_str()?);

    presign_lock.u = Some(u);
    presign_lock.v = Some(v);
    presign_lock.pre_phi = Some(pre_phi.as_ref().to_owned()?);

    println!("[+] Computed u and v");

    Ok(())
}

// 交换 u 和 v
pub fn exchange_u_v(state: &PartyPresignState) -> Result<(), Box<dyn std::error::Error>> {
    // 发送 u 和 v
    send_u_v(state)?;

    // 等待接收上一个参与方的数据
    wait_for_received(state)?;

    let mut presign_lock = state.presign_data.lock().unwrap();
    let recv_lock = state.recv_data.lock().unwrap();

    // 正确处理 Option
    if let Some(pre_u_ref) = recv_lock.pre_u.as_ref() {
        presign_lock.pre_u = Some(pre_u_ref.as_ref().to_owned()?);
    } else {
        return Err("pre_u not received".into());
    }

    if let Some(pre_v_ref) = recv_lock.pre_v.as_ref() {
        presign_lock.pre_v = Some(pre_v_ref.as_ref().to_owned()?);
    } else {
        return Err("pre_v not received".into());
    }

    // 输出 u 和 v 的值（十六进制）
    println!("[+] Received pre_u and pre_v:");
    println!(
        "  pre_u = {}",
        presign_lock.pre_u.as_ref().unwrap().to_hex_str()?
    );
    println!(
        "  pre_v = {}",
        presign_lock.pre_v.as_ref().unwrap().to_hex_str()?
    );

    println!("[+] Exchanged u and v with previous party");
    Ok(())
}

// 发送 u 和 v 给下一个参与方
pub fn send_u_v(state: &PartyPresignState) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let my_id = params.current_party_id as usize;

    // 获取下一个参与方的 ID
    let next_id = if my_id == NUM_PARTIES { 1 } else { my_id + 1 };
    let party = &params.parties[next_id];

    let presign_lock = state.presign_data.lock().unwrap();

    // 确保 u, v 已计算
    let u = presign_lock.u.as_ref().ok_or("u not computed")?;
    let v = presign_lock.v.as_ref().ok_or("v not computed")?;

    // 序列化数据
    let mut buffer = [0u8; 64];
    let u_hex = serialize_bn(u);
    let v_hex = serialize_bn(v);

    buffer[..u_hex.len()].copy_from_slice(&u_hex);
    buffer[32..32 + v_hex.len()].copy_from_slice(&v_hex);

    // 发送消息
    if let Err(e) = send_message(
        my_id as i32,
        &party.ip,
        party.port as u16,
        MessageType::MsgUvData,
        &buffer.to_vec(),
    ) {
        eprintln!("Failed to send to party {}: {}", next_id, e);
    }

    println!("[*] Sent u and v to party {}", next_id);

    Ok(())
}

// 等待接收到数据
fn wait_for_received(state: &PartyPresignState) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let should_break = {
            let is_ready = state.is_ready.lock().unwrap();
            if *is_ready {
                print!("[+] Data received successfully\n");
                true // 标记需要退出循环
            } else {
                false
            }
        };

        if should_break {
            // 重置标志
            let mut is_ready = state.is_ready.lock().unwrap();
            *is_ready = false;
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

// 等待接收协调器的预签名数据
pub fn wait_for_coordinator_data(
    state: &PartyPresignState,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Waiting for coordinator presign data...");
    wait_for_received(state)?;
    println!("[+] Received coordinator presign data");
    Ok(())
}

pub fn run_presign(
    secret_share: &BigNum,
    listen_port: u16,
    party_id: usize,
) -> Result<PresignData, Box<dyn std::error::Error>> {
    // 创建状态
    let state = Arc::new(PartyPresignState::new()?);

    // 设置私钥份额
    {
        let mut presign_lock = state.presign_data.lock().unwrap();
        presign_lock.x = Some(secret_share.as_ref().to_owned()?);
    }
    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_presign_handler(Arc::clone(&state));
    network_service.set_message_handler(handler);

    // 重置退出标志
    crate::common::network::LISTEN_THREAD_EXIT.store(false, Ordering::SeqCst);

    // 启动监听线程
    network_service.start_listen_thread(listen_port)?;

    println!(
        "[*] Party {} started presign phase, listening on port {}",
        party_id, listen_port
    );

    // 等待协调器的预签名数据
    wait_for_coordinator_data(&state)?;

    // 步骤1: 生成 k 和 phi
    generate_k_phi(&state)?;

    // 步骤2: 计算 u 和 v
    compute_u_v(&state, secret_share)?;

    // 步骤3: 交换 u 和 v
    exchange_u_v(&state)?;

    // 步骤4: 计算并广播 R
    public_r(&state)?;

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

    // 获取最终的预签名数据
    let params = get_system_params();
    let group = &params.group;
    let presign_lock = state.presign_data.lock().unwrap();
    let presign_data = PresignData {
        gamma: copy_ec_point_option(&presign_lock.gamma, group)?,
        sw: copy_ec_point_option(&presign_lock.sw, group)?,
        k: copy_bn_option(&presign_lock.k)?,
        phi: copy_bn_option(&presign_lock.phi)?,
        x: copy_bn_option(&presign_lock.x)?,
        r: copy_ec_point_option(&presign_lock.r, group)?,
        sum_r: copy_ec_point_option(&presign_lock.sum_r, group)?,
        big_r: copy_bn_option(&presign_lock.big_r)?,
        u: copy_bn_option(&presign_lock.u)?,
        v: copy_bn_option(&presign_lock.v)?,
        pre_u: copy_bn_option(&presign_lock.pre_u)?,
        pre_phi: copy_bn_option(&presign_lock.pre_phi)?,
        pre_v: copy_bn_option(&presign_lock.pre_v)?,
    };

    println!("[+] Party {} completed presign phase", party_id);

    Ok(presign_data)
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presign_data_new() -> Result<(), Box<dyn std::error::Error>> {
        let presign_data = PresignData::new();
        assert!(presign_data.gamma.is_none());
        assert!(presign_data.sw.is_none());
        assert!(presign_data.k.is_none());

        // 测试初始化
        let mut presign_data = PresignData::new();
        let result = presign_data.init_with_params();
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_generate_k_phi() -> Result<(), Box<dyn std::error::Error>> {
        let state = PartyPresignState::new()?;

        generate_k_phi(&state)?;

        let presign_lock = state.presign_data.lock().unwrap();
        assert!(presign_lock.k.is_some());
        assert!(presign_lock.phi.is_some());

        Ok(())
    }
}
