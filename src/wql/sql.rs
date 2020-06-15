use itertools::Itertools;

use super::tags::{CompareOp, ConjunctionOp, TagName, TagQueryEncoder};
use crate::error::KvResult;

pub struct TagSqlEncoder {
    pub arguments: Vec<Vec<u8>>,
}

impl TagSqlEncoder {
    pub fn new() -> Self {
        // FIXME - encrypt via enclave
        Self { arguments: vec![] }
    }
}

impl TagQueryEncoder for TagSqlEncoder {
    type Arg = Vec<u8>;
    type Clause = String;

    fn encode_name(&mut self, name: &TagName) -> KvResult<Self::Arg> {
        Ok(match name {
            TagName::Encrypted(name) => name.clone(),
            TagName::Plaintext(name) => format!("~{}", name),
        }
        .as_bytes()
        .to_vec())
    }

    fn encode_value(&mut self, value: &String, _is_plaintext: bool) -> KvResult<Self::Arg> {
        Ok(value.as_bytes().to_vec())
    }

    fn encode_op_clause(
        &mut self,
        op: CompareOp,
        enc_name: Self::Arg,
        enc_value: Self::Arg,
        is_plaintext: bool,
    ) -> KvResult<Self::Clause> {
        let query = format!(
            "i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value {} $$ AND plaintext = {})",
            op.as_sql_str(),
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
    fn test_simple_and() {
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
        let mut enc = TagSqlEncoder::new();
        let query_str = query.encode(&mut enc).unwrap();
        assert_eq!(query_str, "((i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value = $$ AND plaintext = 0) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value = $$ AND plaintext = 1)) OR (i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value = $$ AND plaintext = 0) AND i.id IN (SELECT item_id FROM items_tags WHERE name = $$ AND value != $$ AND plaintext = 1)))");
        let args = enc.arguments;
        assert_eq!(
            args,
            vec![
                b"enctag".to_vec(),
                b"encval".to_vec(),
                b"~plaintag".to_vec(),
                b"plainval".to_vec(),
                b"enctag".to_vec(),
                b"encval".to_vec(),
                b"~plaintag".to_vec(),
                b"eggs".to_vec()
            ]
        );
    }
}
