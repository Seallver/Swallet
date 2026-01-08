// party_sign.rs
use crate::common::crypto_utils::{
    copy_bn_option, copy_ec_point, decrypt, encrypt, get_point_x_coordinate, h3, random_in_zq,
    random_in_zq_star,
};
use crate::common::network::{
    deserialize_ec_point, send_message, serialize_ec_point, MessageType, NetworkMessage,
    NetworkService,
};
use crate::common::params::{get_system_params, NUM_PARTIES};
use crate::party::presign::PresignData;
use crossbeam_utils::atomic::AtomicCell;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcPoint;
use openssl::hash::{Hasher, MessageDigest};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

// 全局状态
static SIGN_FLAG: AtomicBool = AtomicBool::new(false);
static OFFLINE_ID_PARTY: AtomicI32 = AtomicI32::new(-1);

// Party 结构体
pub struct Party {
    // 公开参数
    pub a: Option<EcPoint>,
    pub b: Option<EcPoint>,

    pub beta_i: Option<BigNum>,   // 随机数 β_i
    pub delta_i: Option<EcPoint>, // ▲_i = Γ_i^{β_i}
    pub rw_i: Option<EcPoint>,    // rw_i = sw_i^{β_i}
    pub l_i: Option<EcPoint>,     // 从协调者接收的 L_i
    pub m_i: Option<EcPoint>,     // M_i = g^{ν_i} · b^{rw_i}
    pub n_i: Option<EcPoint>,     // N_i = (L_i / a^{rw_i})^{ν_i}
    pub key_i: Option<[u8; 32]>,  // 会话密钥
    pub h_msg: Option<[u8; 32]>,  // H(msg)

    pub sigma_i: Option<BigNum>, // 签名份额 σ_i
}

//状态机状态
#[derive(Clone, Copy, PartialEq)]
enum SignPhase {
    WaitingRequest, // 等待签名请求
    WaitingOffline, // 等待离线信号
    WaitingLMsg,    // 等待L消息
    WaitingCTMsg,   // 等待CT消息
    Completed,      // 完成
}

// 当前状态
static CURRENT_PHASE: AtomicCell<SignPhase> = AtomicCell::new(SignPhase::WaitingRequest);

impl Party {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Party {
            a: None,
            b: None,
            beta_i: None,
            delta_i: None,
            rw_i: None,
            l_i: None,
            m_i: None,
            n_i: None,
            key_i: None,
            h_msg: None,
            sigma_i: None,
        })
    }
}

// 全局 party 实例
pub static PARTY: Mutex<Party> = Mutex::new(Party {
    a: None,
    b: None,
    beta_i: None,
    delta_i: None,
    rw_i: None,
    l_i: None,
    m_i: None,
    n_i: None,
    key_i: None,
    h_msg: None,
    sigma_i: None,
});

// 消息处理器
pub fn create_party_sign_handler() -> Box<dyn Fn(&NetworkMessage) + Send + Sync + 'static> {
    Box::new(move |msg: &NetworkMessage| {
        party_sign_message_handler(msg);
    })
}

fn party_sign_message_handler(msg: &NetworkMessage) {
    match msg.msg_type {
        MessageType::RequestSign => loop {
            if CURRENT_PHASE.load() != SignPhase::WaitingRequest {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            if let Err(e) = handle_request_sign(msg) {
                eprintln!("Error handling RequestSign: {:?}", e);
            }
            SIGN_FLAG.store(true, Ordering::SeqCst);
            break;
        },
        MessageType::SignalOffline => loop {
            if CURRENT_PHASE.load() != SignPhase::WaitingOffline {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            if let Err(e) = handle_signal_offline(msg) {
                eprintln!("Error handling SignalOffline: {:?}", e);
            }
            SIGN_FLAG.store(true, Ordering::SeqCst);
            break;
        },
        MessageType::MsgC2PL => loop {
            if CURRENT_PHASE.load() != SignPhase::WaitingLMsg {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            match handle_l_msg(msg) {
                Ok(_) => {
                    SIGN_FLAG.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Error handling L message: {:?}", e);
                }
            }
            break;
        },
        MessageType::MsgC2PCt => loop {
            if CURRENT_PHASE.load() != SignPhase::WaitingCTMsg {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            match handle_ct_msg(msg) {
                Ok(_) => {
                    SIGN_FLAG.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Error handling CT message: {:?}", e);
                }
            }
            break;
        },
        _ => {
            println!(
                "Received unexpected message type: {} in current phase: {}",
                msg.msg_type.as_str(),
                match CURRENT_PHASE.load() {
                    SignPhase::WaitingRequest => " (WaitingRequest)",
                    SignPhase::WaitingOffline => " (WaitingOffline)",
                    SignPhase::WaitingLMsg => " (WaitingLMsg)",
                    SignPhase::WaitingCTMsg => " (WaitingCTMsg)",
                    SignPhase::Completed => " (Completed)",
                }
            );
        }
    }
}

fn handle_request_sign(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let data_str = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let a_hex = &data_str[0..66];
    let b_hex = &data_str[66..132];

    println!("[*] a hex: {}...", &a_hex);
    println!("[*] b hex: {}...", &b_hex);

    let a = deserialize_ec_point(&a_hex)?;
    let b = deserialize_ec_point(&b_hex)?;

    let mut party_lock = PARTY.lock().unwrap();
    party_lock.a = Some(a);
    party_lock.b = Some(b);

    println!("[*] Party received a and b from coordinator");

    Ok(())
}

fn handle_signal_offline(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let offline_str = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let offline_id: i32 = offline_str
        .parse()
        .map_err(|e| format!("Failed to parse offline_id: {}", e))?;

    OFFLINE_ID_PARTY.store(offline_id, Ordering::SeqCst);
    println!("[*] Party notified that party {} is offline", offline_id);

    Ok(())
}

fn handle_l_msg(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    let l_hex = String::from_utf8_lossy(&msg.data)
        .trim_matches('\0')
        .to_string();

    let l = deserialize_ec_point(&l_hex)?;

    let mut party_lock = PARTY.lock().unwrap();
    party_lock.l_i = Some(l);

    println!("[*] Party received L_i from coordinator");

    Ok(())
}

fn handle_ct_msg(msg: &NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
    if msg.data.len() < 4 {
        return Err("CT data too short".into());
    }

    // 解析长度前缀
    let ct_len = u32::from_be_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]) as usize;

    if msg.data.len() < 4 + ct_len {
        return Err("CT data length mismatch".into());
    }

    let ct = &msg.data[4..4 + ct_len];

    // 获取密钥
    let key = {
        let party_lock = PARTY.lock().unwrap();
        party_lock
            .key_i
            .as_ref()
            .ok_or("Key not available")?
            .clone()
    };

    // 解密
    let plaintext = decrypt(&key, ct)?;

    println!(
        "[+] Decrypted message: {}",
        String::from_utf8_lossy(&plaintext)
    );

    // 计算 H(msg)
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(&plaintext)?;
    let hash = hasher.finish()?;
    let mut h_msg = [0u8; 32];
    h_msg.copy_from_slice(&hash);

    // 存储 H(msg)
    let mut party_lock = PARTY.lock().unwrap();
    party_lock.h_msg = Some(h_msg);

    Ok(())
}

pub fn step2(presign_data: &PresignData) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;

    // 生成 beta
    let beta = random_in_zq_star()?;

    // 计算 delta = Gamma^beta
    let mut delta = EcPoint::new(group)?;
    let gamma = presign_data.gamma.as_ref().to_owned();
    let sw = presign_data.sw.as_ref().to_owned();

    delta.mul(
        group,
        &gamma.ok_or("gamma is not available")?.as_ref(),
        &beta,
        &mut ctx,
    )?;

    // 计算 rw = sw^beta
    let mut rw = EcPoint::new(group)?;
    rw.mul(
        group,
        &sw.ok_or("sw is not available")?.as_ref(),
        &beta,
        &mut ctx,
    )?;

    // 存储到 party
    {
        let mut party_lock = PARTY.lock().unwrap();
        party_lock.beta_i = Some(beta.to_owned()?);
        party_lock.delta_i = Some(delta.to_owned(group)?);
        party_lock.rw_i = Some(rw.to_owned(group)?);
    }

    // 发送 delta 给协调者
    let delta_hex = serialize_ec_point(&delta)?;
    let delta_hex = delta_hex.trim_matches('\0');

    let coordinator = &params.parties[0];

    send_message(
        params.current_party_id as i32,
        &coordinator.ip,
        coordinator.port as u16,
        MessageType::MsgP2CDelta,
        delta_hex.as_bytes(),
    )?;

    println!("[*] Party sent delta_i to coordinator");

    Ok(())
}

pub fn step4() -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let group = &params.group;
    let mut ctx = BigNumContext::new()?;
    let current_party_id = params.current_party_id as usize;

    // 获取需要的值
    let (rw_ref, l_ref, a_ref, b_ref) = {
        let party_lock = PARTY.lock().unwrap();
        (
            copy_ec_point(party_lock.rw_i.as_ref().ok_or("rw_i not available")?)?,
            copy_ec_point(party_lock.l_i.as_ref().ok_or("L_i not available")?)?,
            copy_ec_point(party_lock.a.as_ref().ok_or("a not available")?)?,
            copy_ec_point(party_lock.b.as_ref().ok_or("b not available")?)?,
        )
    };

    // 随机生成 v
    let v = random_in_zq()?;

    // 计算 rw_hash = H3(rw_i)
    let rw_hash = h3(&rw_ref)?;

    // 计算 M_i = g^{v} * b^{rw_hash}
    let mut m_i = EcPoint::new(group)?;
    let mut temp1 = EcPoint::new(group)?;
    let mut temp2 = EcPoint::new(group)?;

    // temp1 = g^{v}
    temp1.mul(group, &params.generator, &v, &mut ctx)?;

    // temp2 = b^{rw_hash}
    temp2.mul(group, &b_ref, &rw_hash, &mut ctx)?;

    // M_i = temp1 + temp2
    m_i.add(group, &temp1, &temp2, &mut ctx)?;

    // 计算 (a^{rw_hash}) 的逆
    let mut a_rw = EcPoint::new(group)?;
    a_rw.mul(group, &a_ref, &rw_hash, &mut ctx)?;
    a_rw.invert(group, &mut ctx)?;

    // 计算 N_i = (L_i * (a^{rw_hash})^{-1})^{v}
    let mut temp = EcPoint::new(group)?;
    temp.add(group, &l_ref, &a_rw, &mut ctx)?;

    let mut n_i = EcPoint::new(group)?;
    n_i.mul(group, &temp, &v, &mut ctx)?;

    // 计算密钥 key_i = H2(rw_i || id_C || id_P || L_i || M_i || N_i)
    let mut hasher = Hasher::new(MessageDigest::sha256())?;

    // 序列化 rw_i
    let rw_bytes = serialize_ec_point(&rw_ref)?;
    hasher.update(&rw_bytes.as_bytes()[..66])?;

    // id_C (coordinator identifier) = 0
    hasher.update(&[0])?;

    // id_P (当前参与方 identifier)
    hasher.update(&[current_party_id as u8])?;

    // 序列化 L_i
    let l_bytes = serialize_ec_point(&l_ref)?;
    hasher.update(&l_bytes.as_bytes()[..66])?;

    // 序列化 M_i
    let m_bytes = serialize_ec_point(&m_i)?;
    hasher.update(&m_bytes.as_bytes()[..66])?;

    // 序列化 N_i
    let n_bytes = serialize_ec_point(&n_i)?;
    hasher.update(&n_bytes.as_bytes()[..66])?;

    let hash_result = hasher.finish()?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_result);

    // 存储到 party
    {
        let mut party_lock = PARTY.lock().unwrap();
        party_lock.m_i = Some(m_i.to_owned(group)?);
        party_lock.n_i = Some(n_i);
        party_lock.key_i = Some(key);
    }

    // 发送 M_i 给协调者
    let m_hex = serialize_ec_point(&m_i)?;
    let m_hex = m_hex.trim_matches('\0');

    let coordinator = &params.parties[0];
    send_message(
        current_party_id as i32,
        &coordinator.ip,
        coordinator.port as u16,
        MessageType::MsgP2CM,
        m_hex.as_bytes(),
    )?;

    println!("[*] Party sent M_i to coordinator");

    Ok(())
}

pub fn step7(presign_data: &PresignData) -> Result<(), Box<dyn std::error::Error>> {
    let params = get_system_params();
    let q = &params.order;
    let mut ctx = BigNumContext::new()?;
    let current_party_id = params.current_party_id as usize;
    let offline_id = OFFLINE_ID_PARTY.load(Ordering::SeqCst) as isize;

    // 获取 H(msg)
    let h_msg = {
        let party_lock = PARTY.lock().unwrap();
        party_lock
            .h_msg
            .as_ref()
            .ok_or("H(msg) not available")?
            .clone()
    };

    // 将 H(msg) 转换为 BigNum
    let mut bn_h = BigNum::from_slice(&h_msg)?;

    // 如果 H(msg) >= q，取模
    if &bn_h >= q {
        let mut temp = BigNum::new()?;
        temp.mod_add(&bn_h, &BigNum::from_u32(0)?.as_ref(), q, &mut ctx)?;
        bn_h = temp;
    }

    // 计算 w 和 u，需要判断上家是否离线
    let (w, u) = if offline_id != -1
        && (offline_id + 1) % NUM_PARTIES as isize == current_party_id as isize
    {
        // i-1 离线的情况
        let mut temp = BigNum::new()?;
        let mut m_phi = BigNum::new()?;
        let mut r_v = BigNum::new()?;
        let mut w = BigNum::new()?;
        let mut u = BigNum::new()?;

        let phi = presign_data.phi.as_ref().to_owned();
        let pre_phi = presign_data.pre_phi.as_ref().to_owned();

        // temp = phi + pre_phi mod q
        temp.mod_add(
            &phi.ok_or("e")?.as_ref(),
            &pre_phi.ok_or("e")?.as_ref(),
            q,
            &mut ctx,
        )?;
        // m_phi = H(msg) * (phi + pre_phi) mod q
        m_phi.mod_mul(&bn_h, &temp, q, &mut ctx)?;

        let v = presign_data.v.as_ref().to_owned();
        let pre_v = presign_data.pre_v.as_ref().to_owned();
        // temp = v + pre_v mod q
        temp.mod_add(
            &v.ok_or("e")?.as_ref(),
            &pre_v.ok_or("e")?.as_ref(),
            q,
            &mut ctx,
        )?;

        // r为R横坐标
        // r_v = r * (v + pre_v) mod q
        let r_point = presign_data.sum_r.as_ref().to_owned();
        let r = get_point_x_coordinate(r_point.ok_or("R is not available")?)?;
        r_v.mod_mul(&r, &temp, q, &mut ctx)?;

        // w = m_phi + r_v mod q
        w.mod_add(&m_phi, &r_v, q, &mut ctx)?;

        // u = u + pre_u mod q
        let p_u = presign_data.u.as_ref().to_owned();
        let p_pre_u = presign_data.pre_u.as_ref().to_owned();
        u.mod_add(
            &p_u.ok_or("e")?.as_ref(),
            &p_pre_u.ok_or("e")?.as_ref(),
            q,
            &mut ctx,
        )?;

        (w, u)
    } else {
        // 其他情况（都在线或不是上家离线）
        let mut m_phi = BigNum::new()?;
        let mut r_v = BigNum::new()?;
        let mut w = BigNum::new()?;

        // m_phi = H(msg) * phi mod q
        let phi = presign_data.phi.as_ref().to_owned();
        m_phi.mod_mul(
            &bn_h,
            &phi.ok_or("phi is not available")?.as_ref(),
            q,
            &mut ctx,
        )?;

        // r_v = r * v mod q
        let r_point = presign_data.sum_r.as_ref().to_owned();
        let r = get_point_x_coordinate(r_point.ok_or("R is not available")?)?;
        let v = presign_data.v.as_ref().to_owned();
        r_v.mod_mul(&r, &v.ok_or("v is not available")?.as_ref(), q, &mut ctx)?;

        // w = m_phi + r_v mod q
        w.mod_add(&m_phi, &r_v, q, &mut ctx)?;

        let u_opt = copy_bn_option(&presign_data.u)?;
        let p_u = u_opt.ok_or("u is not available")?;

        (w, p_u)
    };

    // 准备加密数据：w_len + w + u_len + u
    let w_bytes = w.to_vec();
    let u_bytes = u.to_vec();
    let w_len = w_bytes.len();
    let u_len = u_bytes.len();

    let mut plaintext = Vec::with_capacity(4 + w_len + 4 + u_len);

    // 写入 w 的长度和值
    plaintext.extend_from_slice(&(w_len as u32).to_be_bytes());
    plaintext.extend_from_slice(&w_bytes);

    // 写入 u 的长度和值
    plaintext.extend_from_slice(&(u_len as u32).to_be_bytes());
    plaintext.extend_from_slice(&u_bytes);

    // 获取密钥
    let key = {
        let party_lock = PARTY.lock().unwrap();
        party_lock
            .key_i
            .as_ref()
            .ok_or("Key not available")?
            .clone()
    };

    // 加密
    let ciphertext = encrypt(&key, &plaintext)?;

    // 添加长度前缀
    let ct_len = ciphertext.len() as u32;
    let mut send_buf = Vec::with_capacity(4 + ciphertext.len());
    send_buf.extend_from_slice(&ct_len.to_be_bytes());
    send_buf.extend_from_slice(&ciphertext);

    // 发送给协调者
    let coordinator = &params.parties[0];
    send_message(
        current_party_id as i32,
        &coordinator.ip,
        coordinator.port as u16,
        MessageType::MsgP2CSigma,
        &send_buf,
    )?;

    println!("[*] Party sent encrypted (w, u) to coordinator");

    Ok(())
}

pub fn run_sign(
    presign_data: &PresignData,
    listen_port: u16,
    party_id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建网络服务
    let mut network_service = NetworkService::new();

    // 设置消息处理器
    let handler = create_party_sign_handler();
    network_service.set_message_handler(handler);

    // 重置退出标志
    crate::common::network::LISTEN_THREAD_EXIT.store(false, Ordering::SeqCst);

    // 启动监听线程
    network_service.start_listen_thread(listen_port)?;

    println!(
        "[*] Party {} started presign phase, listening on port {}",
        party_id, listen_port
    );

    CURRENT_PHASE.store(SignPhase::WaitingRequest);
    loop {
        // 检查是否收到签名请求
        if SIGN_FLAG.load(Ordering::SeqCst) {
            SIGN_FLAG.store(false, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    CURRENT_PHASE.store(SignPhase::WaitingOffline);
    loop {
        // 检查是否收到离线信号
        if SIGN_FLAG.load(Ordering::SeqCst) {
            SIGN_FLAG.store(false, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    match step2(presign_data) {
        Ok(_) => println!("[+] Party step2 completed"),
        Err(e) => {
            eprintln!("Error in Party step2: {:?}", e);
            return Err(e);
        }
    }

    CURRENT_PHASE.store(SignPhase::WaitingLMsg);
    loop {
        if SIGN_FLAG.load(Ordering::SeqCst) {
            SIGN_FLAG.store(false, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    match step4() {
        Ok(_) => println!("[+] Party step4 completed"),
        Err(e) => {
            eprintln!("Error in Party step4: {:?}", e);
            return Err(e);
        }
    }

    CURRENT_PHASE.store(SignPhase::WaitingCTMsg);
    loop {
        if SIGN_FLAG.load(Ordering::SeqCst) {
            SIGN_FLAG.store(false, Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    match step7(presign_data) {
        Ok(_) => println!("[+] Party step7 completed"),
        Err(e) => {
            eprintln!("Error in Party step7: {:?}", e);
            return Err(e);
        }
    }

    CURRENT_PHASE.store(SignPhase::Completed);

    // 停止网络服务
    network_service.stop();

    Ok(())
}
