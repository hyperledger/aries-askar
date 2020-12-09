use std::marker::PhantomData;

use itertools::Itertools;

use super::tags::{CompareOp, ConjunctionOp, TagName, TagQueryEncoder};
use crate::error::Result;

pub struct TagSqlEncoder<'e, EN, EV> {
    pub enc_name: EN,
    pub enc_value: EV,
    pub arguments: Vec<Vec<u8>>,
    _pd: PhantomData<&'e ()>,
}

impl<'e, EN, EV> TagSqlEncoder<'e, EN, EV>
where
    EN: Fn(&str) -> Result<Vec<u8>> + 'e,
    EV: Fn(&str) -> Result<Vec<u8>> + 'e,
{
    pub fn new(enc_name: EN, enc_value: EV) -> Self {
        Self {
            enc_name,
            enc_value,
            arguments: vec![],
            _pd: PhantomData,
        }
    }
}

impl<'e, EN, EV> TagQueryEncoder for TagSqlEncoder<'e, EN, EV>
where
    EN: Fn(&str) -> Result<Vec<u8>> + 'e,
    EV: Fn(&str) -> Result<Vec<u8>> + 'e,
{
    type Arg = Vec<u8>;
    type Clause = String;

    fn encode_name(&mut self, name: &TagName) -> Result<Self::Arg> {
        Ok(match name {
            TagName::Encrypted(name) | TagName::Plaintext(name) => (&self.enc_name)(name)?,
        })
    }

    fn encode_value(&mut self, value: &String, is_plaintext: bool) -> Result<Self::Arg> {
        Ok(if is_plaintext {
            value.as_bytes().to_vec()
        } else {
            (&self.enc_value)(value)?
        })
    }

    fn encode_op_clause(
        &mut self,
        op: CompareOp,
        enc_name: Self::Arg,
        enc_value: Self::Arg,
        is_plaintext: bool,
    ) -> Result<Option<Self::Clause>> {
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
        Ok(Some(query))
    }

    fn encode_in_clause(
        &mut self,
        enc_name: Self::Arg,
        enc_values: Vec<Self::Arg>,
        is_plaintext: bool,
        negate: bool,
    ) -> Result<Option<Self::Clause>> {
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
        Ok(Some(query))
    }

    fn encode_exist_clause(
        &mut self,
        enc_name: Self::Arg,
        is_plaintext: bool,
        negate: bool,
    ) -> Result<Option<Self::Clause>> {
        let op = if negate { "NOT EXISTS" } else { "EXISTS" };
        let query = format!(
            "{} (SELECT 1 FROM items_tags WHERE item_id=i.id AND name = $$ AND plaintext = {})",
            op,
            if is_plaintext { 1 } else { 0 }
        );
        self.arguments.push(enc_name);
        Ok(Some(query))
    }

    fn encode_conj_clause(
        &mut self,
        op: ConjunctionOp,
        clauses: Vec<Self::Clause>,
    ) -> Result<Option<Self::Clause>> {
        let qc = clauses.len();
        if qc == 0 {
            if op == ConjunctionOp::Or {
                return Ok(Some("0".to_string()));
            } else {
                return Ok(None);
            }
        }
        let mut s = String::new();
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
        Ok(Some(s))
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
        let query_str = enc.encode_query(&query).unwrap().unwrap();
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
