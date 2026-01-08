use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint, EcPointRef};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use std::fs;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

// 常量定义
pub const HASH_LEN: usize = 32; // SHA-256 输出字节
pub const NUM_PARTIES: usize = 3; // 参与方数目，不算coordinator，目前只支持三方
pub const CONFIG_FILE: &str = "parties.config"; // 网络配置文件名
pub const PASSWORD: &str = "password"; // PAKE 协议注册口令 pw
pub const PASSWORD_PRIME: &str = "password"; // PAKE 协议登录口令 pw'
pub const MESSAGE: &str = "hello world"; // 消息

// 参与方网络地址
#[derive(Debug, Clone)]
pub struct PartyAddress {
    pub ip: String,
    pub port: u16,
}

impl Default for PartyAddress {
    fn default() -> Self {
        PartyAddress {
            ip: "127.0.0.1".to_string(),
            port: 0,
        }
    }
}

// 系统参数结构体 - 使用安全的 Rust 类型

pub struct SystemParams {
    pub group: EcGroup,
    pub generator: EcPoint,
    pub order: BigNum,
    pub hash_algorithm: MessageDigest,

    pub parties: Vec<PartyAddress>,
    pub current_party_id: i32,
}

impl SystemParams {
    /// 创建新的系统参数实例
    pub fn new() -> Result<Self, openssl::error::ErrorStack> {
        // 使用 secp256k1 曲线
        let group = EcGroup::from_curve_name(Nid::SECP256K1)?;

        // 获取生成元
        let generator_ref: &EcPointRef = group.generator();
        let generator = generator_ref.to_owned(&group)?;

        // 获取群的阶
        let mut ctx = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        group.order(&mut order, &mut ctx)?;

        Ok(SystemParams {
            group,
            generator,
            order,
            hash_algorithm: MessageDigest::sha256(),
            parties: vec![PartyAddress::default(); NUM_PARTIES + 1],
            current_party_id: 0,
        })
    }

    /// 获取曲线名称
    pub fn curve_name(&self) -> String {
        "secp256k1".to_string()
    }

    /// 获取哈希算法名称
    pub fn hash_algorithm_name(&self) -> String {
        "SHA-256".to_string()
    }

    /// 设置参与方地址
    pub fn set_party_address(
        &mut self,
        party_id: usize,
        ip: &str,
        port: u16,
    ) -> Result<(), String> {
        if party_id > NUM_PARTIES {
            return Err(format!(
                "Party ID {} exceeds maximum {}",
                party_id, NUM_PARTIES
            ));
        }

        self.parties[party_id] = PartyAddress {
            ip: ip.to_string(),
            port,
        };

        Ok(())
    }

    /// 获取参与方地址
    pub fn get_party_address(&self, party_id: usize) -> Option<&PartyAddress> {
        self.parties.get(party_id)
    }

    /// 加载参与方配置
    pub fn load_party_config(&mut self, config_file: &str, party_id: i32) -> Result<(), String> {
        // 检查文件是否存在，不存在则创建默认配置
        if !Path::new(config_file).exists() {
            println!("Config file not found, creating default: {}", config_file);
            if let Err(e) = self.create_default_config(config_file) {
                return Err(format!("Failed to create default config: {}", e));
            }
        }

        // 读取配置文件
        let content = fs::read_to_string(config_file)
            .map_err(|e| format!("Cannot open config file {}: {}", config_file, e))?;

        let mut parties_loaded = 0;

        for line in content.lines() {
            // 跳过注释和空行
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // 解析配置行
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            match (parts[0].parse::<usize>(), parts[2].parse::<u16>()) {
                (Ok(id), Ok(port)) => {
                    if id <= NUM_PARTIES {
                        self.set_party_address(id, parts[1], port).map_err(|e| {
                            format!("Failed to set party address for ID {}: {}", id, e)
                        })?;
                        parties_loaded += 1;
                    }
                }
                _ => continue,
            }
        }

        if parties_loaded != NUM_PARTIES + 1 {
            return Err(format!(
                "Incomplete configuration: loaded {}/{} parties",
                parties_loaded,
                NUM_PARTIES + 1
            ));
        }

        self.current_party_id = party_id;

        println!("Loaded configuration for {} parties", NUM_PARTIES + 1);
        self.print_network_config();

        Ok(())
    }

    /// 创建默认配置
    pub fn create_default_config(&self, config_file: &str) -> Result<(), String> {
        let mut content = String::new();
        content.push_str("# SilentTS-Lite Parties Configuration\n");
        content.push_str("# Format: [party_id] [ip_address] [port]\n");
        content.push_str("# For local testing, use 127.0.0.1 with different ports\n\n");

        for i in 0..=NUM_PARTIES {
            content.push_str(&format!("{} 127.0.0.1 {}\n", i, 8000 + i));
        }

        fs::write(config_file, content)
            .map_err(|e| format!("Cannot create config file {}: {}", config_file, e))?;

        println!("Created default configuration: {}", config_file);
        Ok(())
    }

    /// 打印网络配置
    pub fn print_network_config(&self) {
        println!("Network configuration:");
        for (i, addr) in self.parties.iter().enumerate() {
            print!("  Party {}: {}:{}", i, addr.ip, addr.port);
            if i == self.current_party_id as usize {
                print!(" (this node)");
            }
            println!();
        }
    }
}

// 修改全局变量类型
pub static SYS_PARAMS: OnceLock<RwLock<SystemParams>> = OnceLock::new();

/// 获取全局系统参数（只读）
pub fn get_system_params() -> std::sync::RwLockReadGuard<'static, SystemParams> {
    let lock = SYS_PARAMS.get_or_init(|| {
        RwLock::new(SystemParams::new().expect("Failed to initialize system parameters"))
    });
    lock.read().expect("RwLock poisoned")
}

/// 获取全局系统参数（可变）
pub fn get_system_params_mut() -> std::sync::RwLockWriteGuard<'static, SystemParams> {
    let lock = SYS_PARAMS.get_or_init(|| {
        RwLock::new(SystemParams::new().expect("Failed to initialize system parameters"))
    });
    lock.write().expect("RwLock poisoned")
}

/// 初始化系统参数（带配置）
pub fn init_system_params() -> Result<(), String> {
    openssl::init();

    // 使用和 get_system_params 相同的初始化逻辑
    let _ = SYS_PARAMS.get_or_init(|| {
        RwLock::new(SystemParams::new().expect("Failed to initialize system parameters"))
    });

    Ok(())
}

/// 便捷函数：加载配置
pub fn load_system_config(config_file: &str, party_id: i32) -> Result<(), String> {
    let mut params = get_system_params_mut();
    params.load_party_config(config_file, party_id)
}
/// 创建并配置系统参数实例（非全局版本）
pub fn create_and_configure_system_params(party_id: i32) -> Result<SystemParams, String> {
    // 创建系统参数
    let mut params =
        SystemParams::new().map_err(|e| format!("Failed to create system params: {}", e))?;

    // 加载配置
    params.load_party_config(CONFIG_FILE, party_id)?;

    Ok(params)
}

/// 打印系统参数信息
pub fn print_system_params() -> Result<(), openssl::error::ErrorStack> {
    let params = get_system_params();

    println!("=== 系统参数 ===");
    println!("曲线: {}", params.curve_name());
    println!("哈希算法: {}", params.hash_algorithm_name());
    println!("参与方数量: {}", NUM_PARTIES);
    println!("当前参与方 ID: {}", params.current_party_id);

    // 打印网络配置
    println!("\n网络配置:");
    for (i, addr) in params.parties.iter().enumerate() {
        println!("  参与方 {}: {}:{}", i, addr.ip, addr.port);
    }

    Ok(())
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_system_params_creation() {
        let result = SystemParams::new();
        assert!(
            result.is_ok(),
            "Failed to create system params: {:?}",
            result.err()
        );

        let params = result.unwrap();
        assert_eq!(params.curve_name(), "secp256k1");
        assert_eq!(params.hash_algorithm_name(), "SHA-256");
        assert_eq!(params.parties.len(), NUM_PARTIES + 1);
    }

    #[test]
    fn test_party_address_management() {
        let mut params = SystemParams::new().unwrap();

        assert!(params.set_party_address(0, "192.168.1.100", 8080).is_ok());
        assert!(params.set_party_address(5, "192.168.1.101", 8081).is_err());

        let addr = params.get_party_address(0).unwrap();
        assert_eq!(addr.ip, "192.168.1.100");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn test_global_params() {
        init_system_params().expect("Failed to init global params");
        let params = get_system_params();
        assert_eq!(params.curve_name(), "secp256k1");
    }

    #[test]
    fn test_config_file_operations() {
        // 创建临时文件
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_str().unwrap();

        let params = SystemParams::new().unwrap();

        // 测试创建默认配置
        assert!(params.create_default_config(config_path).is_ok());

        // 验证文件内容
        let content = fs::read_to_string(config_path).unwrap();
        assert!(content.contains("SilentTS-Lite Parties Configuration"));
        assert!(content.contains("127.0.0.1"));

        // 测试加载配置
        let mut params2 = SystemParams::new().unwrap();
        let result = params2.load_party_config(config_path, 1);
        assert!(result.is_ok(), "Failed to load config: {:?}", result.err());

        // 验证配置已加载
        assert_eq!(params2.current_party_id, 1);
        assert_eq!(params2.parties[0].port, 8000);
        assert_eq!(params2.parties[1].port, 8001);
    }
}
