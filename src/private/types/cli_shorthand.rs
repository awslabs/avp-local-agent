use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, take_till},
    character::complete::{alpha1, multispace0, one_of},
    combinator::{eof, map},
    multi::fold_many1,
    sequence::{delimited, preceded, separated_pair, terminated},
    IResult,
};

///A parser for AWS CLI shorthand structures, particularly those that are used with AVP.
///
/// It uses nom to parse strings that essentially JSON like but shorthand, as used as
/// shorthand structural values in the AWS CLI. This is particularly targeted at the
/// AVP SDK `PolicyFilter` structure in order to allow the caller to easily specify such
/// a structure when constraining the set of policies that are managed by the AVP policy
/// provider.
///
/// See the AVP CLI documentation, and the tests below, for more syntax information.
///
/// The parser performs no String allocations.
///

#[derive(Clone, Debug, PartialEq)]
pub enum Value<'src> {
    Simple(&'src str),
    MaybeEscaped(&'src str),
    Struct(Vec<(&'src str, Value<'src>)>),
}
impl<'src> Value<'src> {
    pub fn is_string(&self) -> bool {
        !matches!(self, Self::Struct(..))
    }

    pub fn to_string(&self) -> Option<String> {
        match self {
            Value::Simple(v) => Some((*v).to_string()),
            Value::MaybeEscaped(v) => Some(v.replace('\\', "")),
            Value::Struct(_) => None,
        }
    }
}

pub type Error = nom::Err<String>;
pub fn from_cli_string(
    input: &str,
) -> Result<Vec<(&str, Value<'_>)>, Error> {
    structure(input).map(|v| v.1).map_err(|e| e.map(|e1| e1.to_string()))
}

/// A structure is a comma-separated list of properties.
///
/// Terminating comma is consumed. Terminating brace is not consumed
///
fn structure(input: &str) -> IResult<&str, Vec<(&str, Value<'_>)>> {
    fold_many1(
		terminated(property, alt((tag(","), take_till(|c| c == '}'), eof))),
		Vec::new,
		|mut acc: Vec<_>, item| {
			acc.push(item);
			acc
		}
	)(input)
}

/// Escaped strings (those inside quotes) MAY have escaped backslashes and embedded quotes
/// escapes are NOT resolved (to avoid allocations at this point)
fn escaped_string(input: &str) -> IResult<&str, &str> {
    escaped(is_not("\\\""), '\\', one_of(r#"\n""#))(input)
}

/// Quoted values are "" with escape semantics
///
/// The bounding quotes are consumed
///
fn quoted_value(input: &str) -> IResult<&str, Value<'_>> {
    map(
        delimited(
            tag(r#"""#),
            escaped_string,
            terminated(tag(r#"""#), multispace0),
        ),
        Value::MaybeEscaped,
    )(input)
}

/// Simple values are unquoted values that are terminated by a "," or a "}"
///
/// The terminating , or } is not consumed
///
fn simple_value(input: &str) -> IResult<&str, Value<'_>> {
    map(is_not(",}\n"), |s: &str| {
        Value::Simple(s.trim_ascii())
    })(input)
}

/// Struct values are brace-delimited
///
/// The bounding braces are consumed
///
fn struct_value(input: &str) -> IResult<&str, Value<'_>> {
    map(
        delimited(tag("{"), structure, preceded(multispace0, tag("}"))),
        Value::Struct,
    )(input)
}

/// Values are strings or braced structures
fn any_value(input: &str) -> IResult<&str, Value<'_>> {
    alt((struct_value, quoted_value, simple_value))(input)
}

/// Property names are alpha
fn property_name(input: &str) -> IResult<&str, &str> {
    alpha1(input)
}

/// Properties are '`property_name` "=" `any_value`' pairs
fn property(input: &str) -> IResult<&str, (&str, Value<'_>)> {
    separated_pair(
        delimited(multispace0, property_name, multispace0),
        tag("="),
        delimited(multispace0, any_value, multispace0),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::Value;

    #[test]
    fn all() {
        let s = r#"principal={unspecified=boolean,identifier={entityType=string,entityId="this is \"string"}},resource={unspecified=boolean,identifier={entityType=string,entityId=string}},policyType=string,policyTemplateId=string"#;
        let r = super::structure(s).expect("Should have parsed");
        assert!(r.0.is_empty(), "Should have consumed the entire string");
    }
    #[test]

    fn all_with_whitespace() {
        let s1 = r#"principal={unspecified=boolean,identifier={entityType=string,entityId="this is \"string"}},resource={unspecified=boolean,identifier={entityType=string,entityId=string}},policyType=string,policyTemplateId=string"#;
        let s2 = r#" 
			principal = { 
				unspecified = boolean , 
				identifier  = 
				{    
					entityType = string, 
					entityId   = "this is \"string"
				} 
			}, 
			resource = { 
				unspecified   =  boolean,  
				identifier = {	
					entityType = string,   
					entityId   =  string  
				}   
			},   
			policyType        = string,  
			policyTemplateId  = string   
		"#;
        let r1 = super::structure(s1).expect("s1 should have parsed");
        let r2 = super::structure(s2).expect("s2 should have parsed");
        assert!(r2.0.is_empty(), "Should have consumed the entire string");
        assert_eq!(
            r1, r2,
            "with and without whitespace should parse to the same value"
        );
    }

    #[test]
    fn no_structs() {
        let s = r"policyType=string1,policyTemplateId=string2";
        let r = super::structure(s).expect("Should have parsed");
        assert!(r.0.is_empty(), "Should have consumed the entire string");
        if let [(k1, v1), (k2, v2)] = r.1.as_slice() {
            assert_eq!(*k1, "policyType");
            assert!(
                matches!(*v1,Value::Simple(v) if v == "string1"),
                "Expected CliShorthandValue::SimpleValue(string1): {v1:#?}"
            );
            assert_eq!(*k2, "policyTemplateId");
            assert!(
                matches!(*v2,Value::Simple(v) if v == "string2"),
                "Expected CliShorthandValue::SimpleValue(string2): {v2:#?}"
            );
        } else {
            assert_eq!(r.1.len(), 2);
        }
    }

    #[test]
    fn only_one_simple() {
        let s = r"policyType=string1";
        let r = super::structure(s).expect("Should have parsed");
        assert!(r.0.is_empty(), "Should have consumed the entire string");
        if let [(k1, v1)] = r.1.as_slice() {
            assert_eq!(*k1, "policyType");
            assert!(
                matches!(*v1,Value::Simple(v) if v == "string1"),
                "Expected CliShorthandValue::SimpleValue(string1): {v1:#?}"
            );
        } else {
            assert_eq!(r.1.len(), 1);
        }
    }

    #[test]
    fn only_one_struct_with_escape() {
        let s = r#"principal={unspecified=boolean,identifier={entityType=string,entityId="this is \"string"}}"#;
        let r = super::structure(s).expect("Should have parsed");
        assert!(r.0.is_empty(), "Should have consumed the entire string");
        if let [(k1, v1)] = r.1.as_slice() {
            assert_eq!(*k1, "principal");
            if let Value::Struct(s) = v1 {
                if let [(f1, f1v), (f2, f2v)] = s.as_slice() {
                    assert_eq!(*f1, "unspecified");
                    assert!(
                        matches!(f1v, Value::Simple("boolean")),
                        "'unspecified' should have a simple value of 'boolean': {f1v:#?}"
                    );
                    assert_eq!(*f2, "identifier");
                    if let Value::Struct(s2) = f2v {
                        if let [(f3, f3v), (f4, f4v)] = s2.as_slice() {
                            assert_eq!(*f3, "entityType");
                            assert!(
                                matches!(f3v, Value::Simple("string")),
                                "'entityType' should have a simple value of 'string': {f3v:#?}"
                            );
                            assert_eq!(*f4, "entityId");
                            assert!(matches!(f4v, Value::MaybeEscaped("this is \\\"string")), "'entityType' should have a 'maybe escaped' value of 'this is \\\"string': {f4v:#?}");
                        } else {
                            panic!("Unable to verify value: {s2:#?}");
                        }
                    } else {
                        panic!("Unable to verify value: {f2v:#?}");
                    }
                } else {
                    panic!("Unable to verify value: {s:#?}");
                }
            } else {
                panic!("Unable to verify value: {v1:#?}");
            }
        } else {
            panic!("Unable to verify value: {:#?}", r.1);
        }
    }
}
