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
use std::result;

use common_query::error::{InvalidFuncArgsSnafu, Result};
use common_query::prelude::{Signature, Volatility};
use datatypes::prelude::ConcreteDataType;
use datatypes::scalars::ScalarVectorBuilder;
use datatypes::types::vector_type_value_to_string;
use datatypes::value::Value;
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
        let datatype = jsons.data_type();
        let mut results = BinaryVectorBuilder::with_capacity(size);
        for i in 0..size {
            let json = jsons.get_ref(i);
            let json = json.as_binary();
            let result = match json {
                Ok(Some(json)) => match jsonb::from_slice(json) {
                    Ok(json) => {
                        let json = json.to_string();
                        Some(json)
                    }
                    Err(_) => {
                        return InvalidFuncArgsSnafu {
                            err_msg: format!("Illegal json binary: {:?}", json),
                        }
                        .fail()
                    }
                },
                _ => None,
            };
            results.push(result.as_ref());

        }
        Ok(results.to_vector())
    }
}

impl Display for JsonToVectorFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", NAME.to_ascii_uppercase())
    }
}

// #[cfg(test)]
// mod tests {
//     use datatypes::value::Value;
//     use datatypes::vectors::BinaryVectorBuilder;

//     use super::*;

//     #[test]
//     fn test_vector_to_string() {
//         let func = JsonToVectorFunction;

//         let mut builder = BinaryVectorBuilder::with_capacity(3);
//         builder.push(Some(
//             [1.0f32, 2.0, 3.0]
//                 .iter()
//                 .flat_map(|e| e.to_le_bytes())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         ));
//         builder.push(Some(
//             [4.0f32, 5.0, 6.0]
//                 .iter()
//                 .flat_map(|e| e.to_le_bytes())
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         ));
//         builder.push_null();
//         let vector = builder.to_vector();

//         let result = func.eval(&FunctionContext::default(), &[vector]).unwrap();

//         assert_eq!(result.len(), 3);
//         assert_eq!(result.get(0), Value::String("[1,2,3]".to_string().into()));
//         assert_eq!(result.get(1), Value::String("[4,5,6]".to_string().into()));
//         assert_eq!(result.get(2), Value::Null);
//     }
// }