//! Java JNI bindings for StreamGuard
//! 
//! Provides native JNI interface for zero-copy performance from Java

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jlong, jint, jobject, jboolean};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::{Decision, Rule};
use crate::engine::GuardEngine;
use crate::rules::sequence::ForbiddenSequenceRule;
use crate::rules::pattern::PatternRule;

// Convert Rust Decision to Java Decision object
fn decision_to_jobject<'a>(env: &'a JNIEnv, decision: &Decision) -> jobject {
    let class = env.find_class("com/streamguard/Decision").unwrap();
    
    match decision {
        Decision::Allow => {
            let method = env.get_static_method_id(
                class,
                "allow",
                "()Lcom/streamguard/Decision;"
            ).unwrap();
            env.call_static_method_unchecked(
                class,
                method,
                jni::signature::JavaType::Object("com/streamguard/Decision".to_string()),
                &[]
            ).unwrap().l().unwrap().into_raw()
        }
        Decision::Block { reason } => {
            let reason_str = env.new_string(reason).unwrap();
            let method = env.get_static_method_id(
                class,
                "block",
                "(Ljava/lang/String;)Lcom/streamguard/Decision;"
            ).unwrap();
            env.call_static_method_unchecked(
                class,
                method,
                jni::signature::JavaType::Object("com/streamguard/Decision".to_string()),
                &[JValue::Object(&JObject::from(reason_str))]
            ).unwrap().l().unwrap().into_raw()
        }
        Decision::Rewrite { replacement } => {
            let text_str = env.new_string(replacement).unwrap();
            let method = env.get_static_method_id(
                class,
                "rewrite",
                "(Ljava/lang/String;)Lcom/streamguard/Decision;"
            ).unwrap();
            env.call_static_method_unchecked(
                class,
                method,
                jni::signature::JavaType::Object("com/streamguard/Decision".to_string()),
                &[JValue::Object(&JObject::from(text_str))]
            ).unwrap().l().unwrap().into_raw()
        }
    }
}

// GuardEngine JNI methods
#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeNew(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let engine = Box::new(GuardEngine::new());
    Box::into_raw(engine) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeNewWithThreshold(
    _env: JNIEnv,
    _class: JClass,
    threshold: jint,
) -> jlong {
    let engine = Box::new(GuardEngine::with_score_threshold(threshold as u32));
    Box::into_raw(engine) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeFeed(
    env: JNIEnv,
    _obj: JObject,
    handle: jlong,
    chunk: JString,
) -> jobject {
    let engine = unsafe { &mut *(handle as *mut GuardEngine) };
    let chunk_str: String = env.get_string(chunk).unwrap().into();
    let decision = engine.feed(&chunk_str);
    decision_to_jobject(&env, &decision)
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeReset(
    _env: JNIEnv,
    _obj: JObject,
    handle: jlong,
) {
    let engine = unsafe { &mut *(handle as *mut GuardEngine) };
    engine.reset();
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeCurrentScore(
    _env: JNIEnv,
    _obj: JObject,
    handle: jlong,
) -> jint {
    let engine = unsafe { &*(handle as *const GuardEngine) };
    engine.current_score() as jint
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeAddForbiddenSequence(
    _env: JNIEnv,
    _obj: JObject,
    handle: jlong,
    rule_handle: jlong,
) {
    let engine = unsafe { &mut *(handle as *mut GuardEngine) };
    let rule = unsafe { Box::from_raw(rule_handle as *mut ForbiddenSequenceRule) };
    engine.add_rule(rule);
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeAddPatternRule(
    _env: JNIEnv,
    _obj: JObject,
    handle: jlong,
    rule_handle: jlong,
) {
    let engine = unsafe { &mut *(handle as *mut GuardEngine) };
    let rule = unsafe { Box::from_raw(rule_handle as *mut PatternRule) };
    engine.add_rule(rule);
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_GuardEngine_nativeDestroy(
    _env: JNIEnv,
    _obj: JObject,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut GuardEngine);
        }
    }
}

// ForbiddenSequenceRule JNI methods
#[no_mangle]
pub extern "system" fn Java_com_streamguard_ForbiddenSequenceRule_nativeStrict(
    env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
) -> jlong {
    let list = env.get_list(tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&env).unwrap() {
        let item = list.get(&env, i).unwrap();
        let s: String = env.get_string(JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::strict(token_vec, reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_ForbiddenSequenceRule_nativeWithGaps(
    env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
) -> jlong {
    let list = env.get_list(tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&env).unwrap() {
        let item = list.get(&env, i).unwrap();
        let s: String = env.get_string(JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::with_gaps(token_vec, reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_ForbiddenSequenceRule_nativeWithScore(
    env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
    score: jint,
) -> jlong {
    let list = env.get_list(tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&env).unwrap() {
        let item = list.get(&env, i).unwrap();
        let s: String = env.get_string(JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::new_with_score(token_vec, reason_str, score as u32));
    Box::into_raw(rule) as jlong
}

// PatternRule JNI methods
#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmail(
    env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(PatternRule::email(reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmailStrict(
    env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(PatternRule::email_strict(reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmailRewrite(
    env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(replacement).unwrap().into();
    let rule = Box::new(PatternRule::email_rewrite(replacement_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeUrl(
    env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(PatternRule::url(reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeUrlRewrite(
    env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(replacement).unwrap().into();
    let rule = Box::new(PatternRule::url_rewrite(replacement_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeIpv4(
    env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(PatternRule::ipv4(reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeIpv4Rewrite(
    env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(replacement).unwrap().into();
    let rule = Box::new(PatternRule::ipv4_rewrite(replacement_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeCreditCard(
    env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(reason).unwrap().into();
    let rule = Box::new(PatternRule::credit_card(reason_str));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeCreditCardRewrite(
    env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(replacement).unwrap().into();
    let rule = Box::new(PatternRule::credit_card_rewrite(replacement_str));
    Box::into_raw(rule) as jlong
}
