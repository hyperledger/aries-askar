use super::{AbstractQuery, Query};
use crate::error::Result as KvResult;

pub type TagQuery = AbstractQuery<TagName, String>;

pub fn tag_query(query: Query) -> KvResult<TagQuery> {
    let result = query
        .map_names(&mut |k| {
            if k.starts_with("~") {
                Ok(TagName::Plaintext(k[1..].to_string()))
            } else {
                Ok(TagName::Encrypted(k))
            }
        })
        .unwrap();
    validate_tag_query(&result)?;
    Ok(result)
}

pub fn validate_tag_query(_query: &TagQuery) -> KvResult<()> {
    // FIXME only equality comparison supported for encrypted keys
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TagName {
    Encrypted(String),
    Plaintext(String),
}

impl ToString for TagName {
    fn to_string(&self) -> String {
        match self {
            Self::Encrypted(v) => v.to_string(),
            Self::Plaintext(v) => format!("~{}", v),
        }
    }
}

impl Into<String> for &TagName {
    fn into(self) -> String {
        self.to_string()
    }
}

pub trait TagQueryEncoder {
    type Arg;
    type Clause;

    fn encode_query(&mut self, query: &TagQuery) -> KvResult<Option<Self::Clause>>
    where
        Self: Sized,
    {
        encode_tag_query(query, self, false)
    }

    fn encode_name(&mut self, name: &TagName) -> KvResult<Self::Arg>;

    fn encode_value(&mut self, value: &String, is_plaintext: bool) -> KvResult<Self::Arg>;

    fn encode_op_clause(
        &mut self,
        op: CompareOp,
        enc_name: Self::Arg,
        enc_value: Self::Arg,
        is_plaintext: bool,
    ) -> KvResult<Option<Self::Clause>>;

    fn encode_in_clause(
        &mut self,
        enc_name: Self::Arg,
        enc_values: Vec<Self::Arg>,
        is_plaintext: bool,
        negate: bool,
    ) -> KvResult<Option<Self::Clause>>;

    fn encode_conj_clause(
        &mut self,
        op: ConjunctionOp,
        clauses: Vec<Self::Clause>,
    ) -> KvResult<Option<Self::Clause>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
    NotLike,
}

impl CompareOp {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Neq => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Like => "LIKE",
            Self::NotLike => "NOT LIKE",
        }
    }

    pub fn as_sql_str_for_prefix(&self) -> Option<&'static str> {
        match self {
            Self::Eq => Some("="),
            Self::Neq => Some("!="),
            Self::Gt | Self::Gte => Some(">="),
            Self::Lt | Self::Lte => Some("<="),
            _ => None,
        }
    }

    pub fn negate(&self) -> Self {
        match self {
            Self::Eq => Self::Neq,
            Self::Neq => Self::Eq,
            Self::Gt => Self::Lte,
            Self::Gte => Self::Lt,
            Self::Lt => Self::Gte,
            Self::Lte => Self::Gt,
            Self::Like => Self::NotLike,
            Self::NotLike => Self::Like,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConjunctionOp {
    And,
    Or,
}

impl ConjunctionOp {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            Self::And => " AND ",
            Self::Or => " OR ",
        }
    }

    pub fn negate(&self) -> Self {
        match self {
            Self::And => Self::Or,
            Self::Or => Self::And,
        }
    }
}

fn encode_tag_query<V, E>(query: &TagQuery, enc: &mut E, negate: bool) -> KvResult<Option<V>>
where
    E: TagQueryEncoder<Clause = V>,
{
    match query {
        TagQuery::Eq(tag_name, target_value) => {
            encode_tag_op(CompareOp::Eq, tag_name, target_value, enc, negate)
        }
        TagQuery::Neq(tag_name, target_value) => {
            encode_tag_op(CompareOp::Neq, tag_name, target_value, enc, negate)
        }
        TagQuery::Gt(tag_name, target_value) => {
            encode_tag_op(CompareOp::Gt, tag_name, target_value, enc, negate)
        }
        TagQuery::Gte(tag_name, target_value) => {
            encode_tag_op(CompareOp::Gte, tag_name, target_value, enc, negate)
        }
        TagQuery::Lt(tag_name, target_value) => {
            encode_tag_op(CompareOp::Lt, tag_name, target_value, enc, negate)
        }
        TagQuery::Lte(tag_name, target_value) => {
            encode_tag_op(CompareOp::Lte, tag_name, target_value, enc, negate)
        }
        TagQuery::Like(tag_name, target_value) => {
            encode_tag_op(CompareOp::Like, tag_name, target_value, enc, negate)
        }
        TagQuery::In(tag_name, target_values) => {
            encode_tag_in(tag_name, target_values, enc, negate)
        }
        TagQuery::And(subqueries) => encode_tag_conj(ConjunctionOp::And, subqueries, enc, negate),
        TagQuery::Or(subqueries) => encode_tag_conj(ConjunctionOp::Or, subqueries, enc, negate),
        TagQuery::Not(subquery) => encode_tag_query(subquery, enc, !negate),
    }
}

fn encode_tag_op<V, E>(
    op: CompareOp,
    name: &TagName,
    value: &String,
    enc: &mut E,
    negate: bool,
) -> KvResult<Option<V>>
where
    E: TagQueryEncoder<Clause = V>,
{
    let is_plaintext = match &name {
        TagName::Plaintext(_) => true,
        _ => false,
    };
    let enc_name = enc.encode_name(name)?;
    let enc_value = enc.encode_value(value, is_plaintext)?;
    let op = if negate { op.negate() } else { op };

    enc.encode_op_clause(op, enc_name, enc_value, is_plaintext)
}

fn encode_tag_in<V, E>(
    name: &TagName,
    values: &Vec<String>,
    enc: &mut E,
    negate: bool,
) -> KvResult<Option<V>>
where
    E: TagQueryEncoder<Clause = V>,
{
    let is_plaintext = match &name {
        TagName::Plaintext(_) => true,
        _ => false,
    };
    let enc_name = enc.encode_name(name)?;
    let enc_values = values
        .into_iter()
        .map(|val| enc.encode_value(val, is_plaintext))
        .collect::<Result<Vec<_>, _>>()?;

    enc.encode_in_clause(enc_name, enc_values, is_plaintext, negate)
}

fn encode_tag_conj<V, E>(
    op: ConjunctionOp,
    subqueries: &Vec<TagQuery>,
    enc: &mut E,
    negate: bool,
) -> KvResult<Option<V>>
where
    E: TagQueryEncoder<Clause = V>,
{
    let op = if negate { op.negate() } else { op };
    let clauses = subqueries
        .into_iter()
        .flat_map(|q| encode_tag_query(q, enc, negate).transpose())
        .collect::<Result<Vec<_>, _>>()?;

    enc.encode_conj_clause(op, clauses)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;
    use crate::wql::Query;

    struct TestEncoder {}

    impl TagQueryEncoder for TestEncoder {
        type Arg = String;
        type Clause = String;

        fn encode_name(&mut self, name: &TagName) -> KvResult<String> {
            Ok(name.to_string())
        }

        fn encode_value(&mut self, value: &String, _is_plaintext: bool) -> KvResult<String> {
            Ok(value.clone())
        }

        fn encode_op_clause(
            &mut self,
            op: CompareOp,
            name: Self::Arg,
            value: Self::Arg,
            _is_plaintext: bool,
        ) -> KvResult<Option<Self::Clause>> {
            Ok(Some(format!("{} {} {}", name, op.as_sql_str(), value)))
        }

        fn encode_in_clause(
            &mut self,
            name: Self::Arg,
            values: Vec<Self::Arg>,
            _is_plaintext: bool,
            negate: bool,
        ) -> KvResult<Option<Self::Clause>> {
            let op = if negate { "NOT IN " } else { "IN" };
            let value = values
                .iter()
                .map(|v| v.as_str())
                .intersperse(", ")
                .collect::<String>();
            Ok(Some(format!("{} {} ({})", name, op, value)))
        }

        fn encode_conj_clause(
            &mut self,
            op: ConjunctionOp,
            clauses: Vec<Self::Clause>,
        ) -> KvResult<Option<Self::Clause>> {
            let mut r = String::new();
            r.push_str("(");
            r.extend(
                clauses
                    .iter()
                    .map(String::as_str)
                    .intersperse(op.as_sql_str()),
            );
            r.push_str(")");
            Ok(Some(r))
        }
    }

    #[test]
    fn test_from_query() {
        let query = Query::And(vec![
            Query::Eq("enctag".to_string(), "encval".to_string()),
            Query::Eq("~plaintag".to_string(), "plainval".to_string()),
        ]);
        let result = tag_query(query).unwrap();
        assert_eq!(
            result,
            TagQuery::And(vec![
                TagQuery::Eq(
                    TagName::Encrypted("enctag".to_string()),
                    "encval".to_string(),
                ),
                TagQuery::Eq(
                    TagName::Plaintext("plaintag".to_string()),
                    "plainval".to_string(),
                ),
            ])
        );
    }

    #[test]
    fn test_serialize() {
        let query = TagQuery::And(vec![
            TagQuery::Eq(
                TagName::Encrypted("enctag".to_string()),
                "encval".to_string(),
            ),
            TagQuery::Eq(
                TagName::Plaintext("plaintag".to_string()),
                "plainval".to_string(),
            ),
        ]);
        let result = serde_json::to_string(&query).unwrap();
        assert_eq!(
            result,
            r#"{"$and":[{"enctag":"encval"},{"~plaintag":"plainval"}]}"#
        );
    }

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
        let query_str = TestEncoder {}.encode_query(&query).unwrap().unwrap();
        assert_eq!(query_str, "((enctag = encval AND ~plaintag = plainval) OR (enctag = encval AND ~plaintag != eggs))")
    }

    #[test]
    fn test_negate_conj() {
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
        let query = TagQuery::Not(Box::new(TagQuery::Or(vec![condition_1, condition_2])));
        let query_str = TestEncoder {}.encode_query(&query).unwrap().unwrap();
        assert_eq!(query_str, "((enctag != encval OR ~plaintag != plainval) AND (enctag != encval OR ~plaintag = eggs))")
    }
}
