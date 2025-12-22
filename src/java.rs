//! Java JNI bindings for StreamGuard
//! 
//! Provides native JNI interface for zero-copy performance from Java

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jlong, jint, jobject};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::core::Decision;
use crate::engine::GuardEngine;
use crate::rules::sequence::ForbiddenSequenceRule;
use crate::rules::pattern::PatternRule;

// Convert Rust Decision to Java Decision object
fn decision_to_jobject<'a>(env: &'a mut JNIEnv, decision: &Decision) -> jobject {
    let class_name = "com/streamguard/Decision";
    
    match decision {
        Decision::Allow => {
            env.call_static_method(
                class_name,
                "allow",
                "()Lcom/streamguard/Decision;",
                &[]
            ).unwrap().l().unwrap().into_raw()
        }
        Decision::Block { reason } => {
            let reason_obj = env.new_string(reason).unwrap();
            env.call_static_method(
                class_name,
                "block",
                "(Ljava/lang/String;)Lcom/streamguard/Decision;",
                &[(&reason_obj).into()]
            ).unwrap().l().unwrap().into_raw()
        }
        Decision::Rewrite { replacement } => {
            let text_obj = env.new_string(replacement).unwrap();
            env.call_static_method(
                class_name,
                "rewrite",
                "(Ljava/lang/String;)Lcom/streamguard/Decision;",
                &[(&text_obj).into()]
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
    mut env: JNIEnv,
    _obj: JObject,
    handle: jlong,
    chunk: JString,
) -> jobject {
    let engine = unsafe { &mut *(handle as *mut GuardEngine) };
    let chunk_str: String = env.get_string(&chunk).unwrap().into();
    let decision = engine.feed(&chunk_str);
    decision_to_jobject(&mut env, &decision)
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
    mut env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
) -> jlong {
    let list = env.get_list(&tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&mut env).unwrap() {
        let item = list.get(&mut env, i).unwrap().unwrap();
        let s: String = env.get_string(&JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::strict(token_vec, reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_ForbiddenSequenceRule_nativeWithGaps(
    mut env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
) -> jlong {
    let list = env.get_list(&tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&mut env).unwrap() {
        let item = list.get(&mut env, i).unwrap().unwrap();
        let s: String = env.get_string(&JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::with_gaps(token_vec, reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_ForbiddenSequenceRule_nativeWithScore(
    mut env: JNIEnv,
    _class: JClass,
    tokens: JObject,
    reason: JString,
    score: jint,
) -> jlong {
    let list = env.get_list(&tokens).unwrap();
    let mut token_vec = Vec::new();
    
    for i in 0..list.size(&mut env).unwrap() {
        let item = list.get(&mut env, i).unwrap().unwrap();
        let s: String = env.get_string(&JString::from(item)).unwrap().into();
        token_vec.push(s);
    }
    
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(ForbiddenSequenceRule::new_with_score(token_vec, reason_str.as_str(), score as u32));
    Box::into_raw(rule) as jlong
}

// PatternRule JNI methods
#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmail(
    mut env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(PatternRule::email(reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmailStrict(
    mut env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(PatternRule::email_strict(reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeEmailRewrite(
    mut env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(&replacement).unwrap().into();
    let rule = Box::new(PatternRule::email_rewrite(replacement_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeUrl(
    mut env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(PatternRule::url(reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeUrlRewrite(
    mut env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(&replacement).unwrap().into();
    let rule = Box::new(PatternRule::url_rewrite(replacement_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeIpv4(
    mut env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(PatternRule::ipv4(reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeIpv4Rewrite(
    mut env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(&replacement).unwrap().into();
    let rule = Box::new(PatternRule::ipv4_rewrite(replacement_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeCreditCard(
    mut env: JNIEnv,
    _class: JClass,
    reason: JString,
) -> jlong {
    let reason_str: String = env.get_string(&reason).unwrap().into();
    let rule = Box::new(PatternRule::credit_card(reason_str.as_str()));
    Box::into_raw(rule) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_streamguard_PatternRule_nativeCreditCardRewrite(
    mut env: JNIEnv,
    _class: JClass,
    replacement: JString,
) -> jlong {
    let replacement_str: String = env.get_string(&replacement).unwrap().into();
    let rule = Box::new(PatternRule::credit_card_rewrite(replacement_str.as_str()));
    Box::into_raw(rule) as jlong
}
