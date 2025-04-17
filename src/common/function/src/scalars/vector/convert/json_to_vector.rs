// Copyright 2025 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::Display;

use common_query::error::{InvalidFuncArgsSnafu, Result};
use common_query::prelude::{Signature, Volatility};
use datatypes::prelude::ConcreteDataType;
use datatypes::scalars::ScalarVectorBuilder;
use datatypes::vectors::{MutableVector, BinaryVectorBuilder, VectorRef};
use snafu::ensure;

use crate::function::{Function, FunctionContext};

const NAME: &str = "json_to_vec";

#[derive(Debug, Clone, Default)]
pub struct JsonToVectorFunction;

impl Function for JsonToVectorFunction {
    fn name(&self) -> &str {
        NAME
    }

    fn return_type(&self, _input_types: &[ConcreteDataType]) -> Result<ConcreteDataType> {
        Ok(ConcreteDataType::binary_datatype())
    }

    fn signature(&self) -> Signature {
        Signature::exact(
            vec![ConcreteDataType::json_datatype()],
            Volatility::Immutable,
        )
    }

    fn eval(&self, _func_ctx: &FunctionContext, columns: &[VectorRef]) -> Result<VectorRef> {
        ensure!(
            columns.len() == 1,
            InvalidFuncArgsSnafu {
                err_msg: format!(
                    "The length of the args is not correct, expect exactly one, have: {}",
                    columns.len()
                ),
            }
        );
        let jsons = &columns[0];

        let size = jsons.len();
        // let _datatype = jsons.data_type();
        let mut results = BinaryVectorBuilder::with_capacity(size);
        for i in 0..size {
            let json = jsons.get_ref(i);
            let json = json.as_binary();
            let result = match json {
                Ok(Some(json_bin)) => {
                    // 3. 尝试从 json binary 解析成 JSON 值
                    match jsonb::from_slice(json_bin) {
                        Ok(json_val) => {
                            // 4. 是否是 array
                            if let Some(array) = json_val.as_array() {
                                let mut vec = Vec::new();
                                for elem in array {
                                    if let Some(v) = elem.as_f64() {
                                        vec.push(v as f32);
                                    } else {
                                        // 有不是 float 的值，整个 vec 判定无效
                                        return InvalidFuncArgsSnafu {
                                            err_msg: format!("Non-float element in array: {elem}"),
                                        }
                                        .fail();
                                    }
                                }
                                // 5. 将 Vec<f32> 安全转换为 Vec<u8>
                                let bytes = if cfg!(target_endian = "little") {
                                    // 如果是小端，直接转为 &[u8]
                                    unsafe {
                                        std::slice::from_raw_parts(
                                            vec.as_ptr() as *const u8,
                                            vec.len() * std::mem::size_of::<f32>(),
                                        )
                                        .to_vec()
                                    }
                                } else {
                                    // 大端系统逐个转字节（兼容性处理）
                                    vec.iter()
                                        .flat_map(|v| v.to_le_bytes())
                                        .collect::<Vec<u8>>()
                                };

                                Some(bytes)
                                // Some(vec)
                            } else {
                                // 不是 array
                                None
                            }
                        }
                        Err(_) => {
                            return InvalidFuncArgsSnafu {
                                err_msg: format!("Illegal json binary: {:?}", json_bin),
                            }
                            .fail();
                        }
                    }
                }
                _ => None, // Binary 为 None 或错误
            };

            // 5. 根据解析结果 push 到结果集
            match result {
                Some(vec) => results.push(Some(vec.as_slice())),
                None => results.push_null(),
            }

        }
        Ok(results.to_vector())
    }
}

impl Display for JsonToVectorFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", NAME.to_ascii_uppercase())
    }
}

#[cfg(test)]
mod tests {

    use datatypes::value::Value;
    use datatypes::vectors::{BinaryVectorBuilder, VectorRef};
    use common_query::prelude::TypeSignature;
    use datatypes::prelude::ConcreteDataType;

    use super::*;

    #[test]
    fn test_json_to_vector() {
        let func = JsonToVectorFunction;
    
        // 检查函数名称
        assert_eq!("json_to_vec", func.name());
    
        // 检查输入输出类型
        assert_eq!(
            ConcreteDataType::binary_datatype(),
            func.return_type(&[ConcreteDataType::json_datatype()]).unwrap()
        );
    
        // 检查签名
        assert!(matches!(func.signature(),
            Signature {
                type_signature: TypeSignature::Exact(valid_types),
                volatility: Volatility::Immutable
            } if valid_types == vec![ConcreteDataType::json_datatype()]
        ));
    
        // 准备三组 JSON 字符串，每个都是浮点数组
        let json_strings = [
            r#"[1.0, 2.0, 3.0]"#,
            r#"[4.0, 5.0, 6.0]"#,
            r#"null"#,
        ];
    
        // 转成 jsonb 二进制格式
        let jsonbs = json_strings
            .iter()
            .map(|s| {
                if *s == "null" {
                    None
                } else {
                    let value = jsonb::parse_value(s.as_bytes()).unwrap();
                    Some(value.to_vec())
                }
            })
            .collect::<Vec<_>>();
    
        // 构建 BinaryVector
        let mut jsonb_builder = BinaryVectorBuilder::with_capacity(jsonbs.len());
        for item in &jsonbs {
            match item {
                Some(b) => jsonb_builder.push(Some(b.as_slice())),
                None => jsonb_builder.push_null(),
            }
        }
        let json_vector = jsonb_builder.to_vector();
    
        // 执行函数
        let args: Vec<VectorRef> = vec![json_vector];
        let result_vector = func.eval(&FunctionContext::default(), &args).unwrap();
    
        assert_eq!(result_vector.len(), 3);
    
        // 预期值作为字符串
        let expected_strs = [
            Some("[1.0, 2.0, 3.0]"),
            Some("[4.0, 5.0, 6.0]"),
            None,
        ];
    
        // 工具函数：将 Value::Binary 解析成 Vec<f32> 字符串
        fn value_to_f32_str(val: &Value) -> String {
            match val {
                Value::Binary(bytes) => {
                    let floats: Vec<f32> = bytes
                        .chunks(4)
                        .map(|chunk| {
                            let arr: [u8; 4] = chunk.try_into().unwrap();
                            f32::from_le_bytes(arr)
                        })
                        .collect();
                    format!("{:?}", floats)
                }
                _ => panic!("Expected binary value"),
            }
        }
    
        // 开始验证
        for (i, expected) in expected_strs.iter().enumerate() {
            let val = result_vector.get(i);
            match expected {
                Some(s) => {
                    let actual_str = value_to_f32_str(&val);
                    assert_eq!(actual_str, *s);
                }
                None => {
                    assert!(val.is_null());
                }
            }
        }
    }
    
}
