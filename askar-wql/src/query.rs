#![deny(missing_debug_implementations, missing_docs)]

/// An abstract query representation over a key and value type
#[derive(Debug, Hash, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbstractQuery<K, V> {
    /// Logical AND of multiple clauses
    And(Vec<Self>),
    /// Logical OR of multiple clauses
    Or(Vec<Self>),
    /// Negation of a clause
    Not(Box<Self>),
    /// Equality comparison for a field value
    Eq(K, V),
    /// Inequality comparison for a field value
    Neq(K, V),
    /// Greater-than comparison for a field value
    Gt(K, V),
    /// Greater-than-or-equal comparison for a field value
    Gte(K, V),
    /// Less-than comparison for a field value
    Lt(K, V),
    /// Less-than-or-equal comparison for a field value
    Lte(K, V),
    /// SQL 'LIKE'-compatible string comparison for a field value
    Like(K, V),
    /// Match one of multiple field values in a set
    In(K, Vec<V>),
    /// Match any non-null field value of the given field names
    Exist(Vec<K>),
}

/// A concrete query implementation with String keys and values
pub type Query = AbstractQuery<String, String>;

impl<K, V> AbstractQuery<K, V> {
    /// Perform basic query clause optimization
    pub fn optimise(self) -> Option<Self> {
        match self {
            Self::Not(boxed_query) => match boxed_query.optimise() {
                None => None,
                Some(Self::Not(nested_query)) => Some(*nested_query),
                Some(other) => Some(Self::Not(Box::new(other))),
            },
            Self::And(subqueries) => {
                let mut subqueries: Vec<Self> = subqueries
                    .into_iter()
                    .flat_map(|query| query.optimise())
                    .collect();

                match subqueries.len() {
                    0 => None,
                    1 => Some(subqueries.remove(0)),
                    _ => Some(Self::And(subqueries)),
                }
            }
            Self::Or(subqueries) => {
                let mut subqueries: Vec<Self> = subqueries
                    .into_iter()
                    .flat_map(|query| query.optimise())
                    .collect();

                match subqueries.len() {
                    0 => None,
                    1 => Some(subqueries.remove(0)),
                    _ => Some(Self::Or(subqueries)),
                }
            }
            Self::In(key, mut targets) if targets.len() == 1 => {
                Some(Self::Eq(key, targets.remove(0)))
            }
            other => Some(other),
        }
    }

    /// Perform a transformation on all field names in query clauses
    pub fn map_names<RK, E>(
        self,
        mut f: impl FnMut(K) -> Result<RK, E>,
    ) -> Result<AbstractQuery<RK, V>, E> {
        self.map(&mut f, &mut |_k, v| Ok(v))
    }

    /// Perform a transformation on all field values in query clauses
    pub fn map_values<RV, E>(
        self,
        mut f: impl FnMut(&K, V) -> Result<RV, E>,
    ) -> Result<AbstractQuery<K, RV>, E> {
        self.map(&mut |k| Ok(k), &mut f)
    }

    /// Transform all query clauses using field name and value conversions
    pub fn map<RK, RV, KF, VF, E>(
        self,
        kf: &mut KF,
        vf: &mut VF,
    ) -> Result<AbstractQuery<RK, RV>, E>
    where
        KF: FnMut(K) -> Result<RK, E>,
        VF: FnMut(&K, V) -> Result<RV, E>,
    {
        match self {
            Self::Eq(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Eq(kf(tag_name)?, tag_value))
            }
            Self::Neq(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Neq(kf(tag_name)?, tag_value))
            }
            Self::Gt(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Gt(kf(tag_name)?, tag_value))
            }
            Self::Gte(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Gte(kf(tag_name)?, tag_value))
            }
            Self::Lt(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Lt(kf(tag_name)?, tag_value))
            }
            Self::Lte(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Lte(kf(tag_name)?, tag_value))
            }
            Self::Like(tag_name, tag_value) => {
                let tag_value = vf(&tag_name, tag_value)?;
                Ok(AbstractQuery::<RK, RV>::Like(kf(tag_name)?, tag_value))
            }
            Self::In(tag_name, tag_values) => {
                let tag_values = tag_values
                    .into_iter()
                    .map(|value| vf(&tag_name, value))
                    .collect::<Result<Vec<_>, E>>()?;
                Ok(AbstractQuery::<RK, RV>::In(kf(tag_name)?, tag_values))
            }
            Self::Exist(tag_names) => Ok(AbstractQuery::<RK, RV>::Exist(
                tag_names.into_iter().try_fold(vec![], |mut v, tag_name| {
                    v.push(kf(tag_name)?);
                    Result::<_, E>::Ok(v)
                })?,
            )),
            Self::And(subqueries) => {
                let subqueries = subqueries
                    .into_iter()
                    .map(|query| query.map(kf, vf))
                    .collect::<Result<Vec<_>, E>>()?;
                Ok(AbstractQuery::<RK, RV>::And(subqueries))
            }
            Self::Or(subqueries) => {
                let subqueries = subqueries
                    .into_iter()
                    .map(|query| query.map(kf, vf))
                    .collect::<Result<Vec<_>, E>>()?;
                Ok(AbstractQuery::<RK, RV>::Or(subqueries))
            }
            Self::Not(boxed_query) => Ok(AbstractQuery::<RK, RV>::Not(Box::new(
                boxed_query.map(kf, vf)?,
            ))),
        }
    }
}

impl<K, V> Default for AbstractQuery<K, V> {
    fn default() -> Self {
        Self::And(Vec::new())
    }
}

#[cfg(feature = "serde_support")]
mod serde_support {
    use std::string;

    use serde::ser::{Serialize, Serializer};
    use serde::{de, Deserialize, Deserializer};
    use serde_json::{self, json, Value as JsonValue};

    use super::{AbstractQuery, Query};

    impl<K, V> Serialize for AbstractQuery<K, V>
    where
        for<'a> &'a K: Into<String>,
        V: Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.to_value().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Query {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let v = JsonValue::deserialize(deserializer)?;

            match v {
                JsonValue::Object(map) => {
                    parse_query(map).map_err(|err| de::Error::missing_field(err))
                }
                JsonValue::Array(array) => {
                    // cast old restrictions format to wql
                    let mut res: Vec<JsonValue> = Vec::new();
                    for sub_query in array {
                        let sub_query: serde_json::Map<String, JsonValue> = sub_query
                            .as_object()
                            .ok_or_else(|| de::Error::custom("Restriction is invalid"))?
                            .clone()
                            .into_iter()
                            .filter(|&(_, ref v)| !v.is_null())
                            .collect();

                        if !sub_query.is_empty() {
                            res.push(JsonValue::Object(sub_query));
                        }
                    }

                    let mut map = serde_json::Map::new();
                    map.insert("$or".to_string(), JsonValue::Array(res));

                    parse_query(map).map_err(|err| de::Error::custom(err))
                }
                _ => Err(de::Error::missing_field(
                    "Restriction must be either object or array",
                )),
            }
        }
    }

    impl<K, V> AbstractQuery<K, V>
    where
        for<'a> &'a K: Into<String>,
        V: Serialize,
    {
        fn to_value(&self) -> JsonValue {
            match self {
                Self::Eq(ref tag_name, ref tag_value) => json!({ tag_name: tag_value }),
                Self::Neq(ref tag_name, ref tag_value) => json!({tag_name: {"$neq": tag_value}}),
                Self::Gt(ref tag_name, ref tag_value) => json!({tag_name: {"$gt": tag_value}}),
                Self::Gte(ref tag_name, ref tag_value) => json!({tag_name: {"$gte": tag_value}}),
                Self::Lt(ref tag_name, ref tag_value) => json!({tag_name: {"$lt": tag_value}}),
                Self::Lte(ref tag_name, ref tag_value) => json!({tag_name: {"$lte": tag_value}}),
                Self::Like(ref tag_name, ref tag_value) => json!({tag_name: {"$like": tag_value}}),
                Self::In(ref tag_name, ref tag_values) => json!({tag_name: {"$in":tag_values}}),
                Self::Exist(ref tag_names) => {
                    json!({ "$exist": tag_names.iter().map(Into::into).collect::<Vec<String>>() })
                }
                Self::And(ref queries) => {
                    if !queries.is_empty() {
                        json!({
                            "$and": queries.iter().map(|q| q.to_value()).collect::<Vec<JsonValue>>()
                        })
                    } else {
                        json!({})
                    }
                }
                Self::Or(ref queries) => {
                    if !queries.is_empty() {
                        json!({
                            "$or": queries.iter().map(|q| q.to_value()).collect::<Vec<JsonValue>>()
                        })
                    } else {
                        json!({})
                    }
                }
                Self::Not(ref query) => json!({"$not": query.to_value()}),
            }
        }
    }

    impl string::ToString for Query {
        fn to_string(&self) -> String {
            self.to_value().to_string()
        }
    }

    fn parse_query(map: serde_json::Map<String, JsonValue>) -> Result<Query, &'static str> {
        let mut operators: Vec<Query> = Vec::new();

        for (key, value) in map {
            if let Some(operator_) = parse_operator(key, value)? {
                operators.push(operator_);
            }
        }

        let query = if operators.len() == 1 {
            operators.remove(0)
        } else {
            Query::And(operators)
        };

        Ok(query)
    }

    fn parse_operator(key: String, value: JsonValue) -> Result<Option<Query>, &'static str> {
        match (key.as_str(), value) {
            ("$and", JsonValue::Array(values)) => {
                if values.is_empty() {
                    Ok(None)
                } else {
                    let operators: Vec<Query> = parse_list_operators(values)?;
                    Ok(Some(Query::And(operators)))
                }
            }
            ("$and", _) => Err("$and must be array of JSON objects"),
            ("$or", JsonValue::Array(values)) => {
                if values.is_empty() {
                    Ok(None)
                } else {
                    let operators: Vec<Query> = parse_list_operators(values)?;
                    Ok(Some(Query::Or(operators)))
                }
            }
            ("$or", _) => Err("$or must be array of JSON objects"),
            ("$not", JsonValue::Object(map)) => {
                let operator = parse_query(map)?;
                Ok(Some(Query::Not(Box::new(operator))))
            }
            ("$not", _) => Err("$not must be JSON object"),
            ("$exist", JsonValue::String(key)) => Ok(Some(Query::Exist(vec![key]))),
            ("$exist", JsonValue::Array(keys)) => {
                if keys.is_empty() {
                    Ok(None)
                } else {
                    let mut ks = vec![];
                    for key in keys {
                        if let JsonValue::String(key) = key {
                            ks.push(key);
                        } else {
                            return Err("$exist must be used with a string or array of strings");
                        }
                    }
                    Ok(Some(Query::Exist(ks)))
                }
            }
            ("$exist", _) => Err("$exist must be used with a string or array of strings"),
            (_, JsonValue::String(value)) => Ok(Some(Query::Eq(key, value))),
            (_, JsonValue::Object(map)) => {
                if map.len() == 1 {
                    let (operator_name, value) = map.into_iter().next().unwrap();
                    parse_single_operator(operator_name, key, value).map(|operator| Some(operator))
                } else {
                    Err("value must be JSON object of length 1")
                }
            }
            (_, _) => Err("Unsupported value"),
        }
    }

    fn parse_list_operators(operators: Vec<JsonValue>) -> Result<Vec<Query>, &'static str> {
        let mut out_operators: Vec<Query> = Vec::with_capacity(operators.len());

        for value in operators.into_iter() {
            if let JsonValue::Object(map) = value {
                let subquery = parse_query(map)?;
                out_operators.push(subquery);
            } else {
                return Err("operator must be array of JSON objects");
            }
        }

        Ok(out_operators)
    }

    fn parse_single_operator(
        operator_name: String,
        key: String,
        value: JsonValue,
    ) -> Result<Query, &'static str> {
        match (&*operator_name, value) {
            ("$neq", JsonValue::String(value_)) => Ok(Query::Neq(key, value_)),
            ("$neq", _) => Err("$neq must be used with string"),
            ("$gt", JsonValue::String(value_)) => Ok(Query::Gt(key, value_)),
            ("$gt", _) => Err("$gt must be used with string"),
            ("$gte", JsonValue::String(value_)) => Ok(Query::Gte(key, value_)),
            ("$gte", _) => Err("$gte must be used with string"),
            ("$lt", JsonValue::String(value_)) => Ok(Query::Lt(key, value_)),
            ("$lt", _) => Err("$lt must be used with string"),
            ("$lte", JsonValue::String(value_)) => Ok(Query::Lte(key, value_)),
            ("$lte", _) => Err("$lte must be used with string"),
            ("$like", JsonValue::String(value_)) => Ok(Query::Like(key, value_)),
            ("$like", _) => Err("$like must be used with string"),
            ("$in", JsonValue::Array(values)) => {
                let mut target_values: Vec<String> = Vec::with_capacity(values.len());

                for v in values.into_iter() {
                    if let JsonValue::String(s) = v {
                        target_values.push(s);
                    } else {
                        return Err("$in must be used with array of strings");
                    }
                }

                Ok(Query::In(key, target_values))
            }
            ("$in", _) => Err("$in must be used with array of strings"),
            (_, _) => Err("Unknown operator"),
        }
    }
}

