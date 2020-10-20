use itertools::Itertools;

use super::tags::{CompareOp, ConjunctionOp, TagName, TagQueryEncoder};
use crate::error::Result as KvResult;

pub struct TagSqlEncoder {
    pub enc_name: Box<dyn FnMut(&str) -> KvResult<Vec<u8>>>,
    pub enc_value: Box<dyn FnMut(&str) -> KvResult<Vec<u8>>>,
    pub arguments: Vec<Vec<u8>>,
}

impl TagSqlEncoder {
    pub fn new(
        enc_name: impl FnMut(&str) -> KvResult<Vec<u8>> + 'static,
        enc_value: impl FnMut(&str) -> KvResult<Vec<u8>> + 'static,
    ) -> Self {
        Self {
            enc_name: Box::new(enc_name),
            enc_value: Box::new(enc_value),
            arguments: vec![],
        }
    }
}

impl TagQueryEncoder for TagSqlEncoder {
    type Arg = Vec<u8>;
    type Clause = String;

    fn encode_name(&mut self, name: &TagName) -> KvResult<Self::Arg> {
        Ok(match name {
            TagName::Encrypted(name) | TagName::Plaintext(name) => (self.enc_name)(name)?,
        })
    }

    fn encode_value(&mut self, value: &String, is_plaintext: bool) -> KvResult<Self::Arg> {
        Ok(if is_plaintext {
            value.as_bytes().to_vec()
        } else {
            (self.enc_value)(value)?
        })
    }

    fn encode_op_clause(
        &mut self,
        op: CompareOp,
        enc_name: Self::Arg,
        enc_value: Self::Arg,
        is_plaintext: bool,
    ) -> KvResult<Self::Clause> {
        let idx = self.arguments.len();
        let op_prefix = op.as_sql_str_for_prefix().map(|pfx_op| {
            format!(
                "AND SUBSTR(value, 0, 12) {} SUBSTR(${}, 0, 12)",
                pfx_op,
                idx + 2
            )
        });
        let query = format!(
            "i.id IN (SELECT item_id FROM items_tags WHERE name = ${} AND value {} ${} {} AND plaintext = {})",
            idx + 1,
            op.as_sql_str(),
            idx + 2,
            op_prefix.as_ref().map(String::as_str).unwrap_or_default(),
            if is_plaintext { 1 } else { 0 }
        );
        self.arguments.push(enc_name);
        self.arguments.push(enc_value);
        Ok(query)
    }

    fn encode_in_clause(
        &mut self,
        enc_name: Self::Arg,
        enc_values: Vec<Self::Arg>,
        is_plaintext: bool,
        negate: bool,
    ) -> KvResult<Self::Clause> {
        let args_in = std::iter::repeat("$$")
            .take(enc_values.len())
            .intersperse(", ")
            .collect::<String>();
        let query = format!(
            "i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value {} ({}) AND plaintext = {})",
            if negate { "NOT IN" } else { "IN" },
            args_in,
            if is_plaintext { 1 } else { 0 }
        );
        self.arguments.push(enc_name);
        self.arguments.extend(enc_values);
        Ok(query)
    }

    fn encode_conj_clause(
        &mut self,
        op: ConjunctionOp,
        clauses: Vec<Self::Clause>,
    ) -> KvResult<Self::Clause> {
        let mut s = String::new();
        let qc = clauses.len();
        if qc > 1 {
            s.push('(');
        }
        for (index, clause) in clauses.into_iter().enumerate() {
            if index > 0 {
                s.push_str(op.as_sql_str());
            }
            s.push_str(&clause);
        }
        if qc > 1 {
            s.push(')');
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tags::TagQuery;
    use super::*;

    #[test]
    fn tag_query_encode() {
        let condition_1 = TagQuery::And(vec![
            TagQuery::Eq(
                TagName::Encrypted("enctag".to_string()),
                "encval".to_string(),
            ),
            TagQuery::Eq(
                TagName::Plaintext("plaintag".to_string()),
                "plainval".to_string(),
            ),
        ]);
        let condition_2 = TagQuery::And(vec![
            TagQuery::Eq(
                TagName::Encrypted("enctag".to_string()),
                "encval".to_string(),
            ),
            TagQuery::Not(Box::new(TagQuery::Eq(
                TagName::Plaintext("plaintag".to_string()),
                "eggs".to_string(),
            ))),
        ]);
        let query = TagQuery::Or(vec![condition_1, condition_2]);
        let mut enc = TagSqlEncoder::new(
            |name: &str| Ok(format!("--{}--", name).into_bytes()),
            |value: &str| Ok(format!("~~{}~~", value).into_bytes()),
        );
        let query_str = enc.encode_query(&query).unwrap();
        assert_eq!(query_str, "((i.id IN (SELECT item_id FROM items_tags WHERE name = $1 AND value = $2 AND SUBSTR(value, 0, 12) = SUBSTR($2, 0, 12) AND plaintext = 0) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $3 AND value = $4 AND SUBSTR(value, 0, 12) = SUBSTR($4, 0, 12) AND plaintext = 1)) OR (i.id IN (SELECT item_id FROM items_tags WHERE name = $5 AND value = $6 AND SUBSTR(value, 0, 12) = SUBSTR($6, 0, 12) AND plaintext = 0) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $7 AND value != $8 AND SUBSTR(value, 0, 12) != SUBSTR($8, 0, 12) AND plaintext = 1)))");
        let args = enc.arguments;
        assert_eq!(
            args,
            vec![
                b"--enctag--".to_vec(),
                b"~~encval~~".to_vec(),
                b"--plaintag--".to_vec(),
                b"plainval".to_vec(),
                b"--enctag--".to_vec(),
                b"~~encval~~".to_vec(),
                b"--plaintag--".to_vec(),
                b"eggs".to_vec()
            ]
        );
    }
}
