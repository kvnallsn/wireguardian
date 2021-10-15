//! Integration Tests

use crate::models::{Session, User};
use color_eyre::eyre;
use std::time::Duration;

#[tokio::test]
async fn single_user_flow_1() -> eyre::Result<()> {
    let (db, users) = crate::tests::setup().await?;

    // login as user 1 successfully
    let user = &users[0];
    let r = User::fetch_and_validate(&db, &user.email, &user.password, user.totp.code()?).await;
    assert!(
        r.is_ok(),
        "failed to fetch and validate user: {:?}",
        r.unwrap_err()
    );
    let r = r.unwrap();

    // validate user matches who we think
    assert_eq!(
        r.username, user.username,
        "username of fetched user doesn't match expected value, fetched wrong user?"
    );
    assert_eq!(
        r.email, user.email,
        "email of fetched user doesn't match expected value, fetched wrong user?"
    );

    // attempt to create a session
    let session = Session::create(&db, &r, [192, 168, 0, 100].into()).await?;
    assert!(!session.is_expired(), "sessions should not start expired");

    // wait one seconds then expire the session
    tokio::time::sleep(Duration::from_secs(1)).await;
    session.expire(&db).await?;

    Ok(())
}

#[tokio::test]
async fn two_user_flow_1() -> eyre::Result<()> {
    let (db, users) = crate::tests::setup().await?;

    // login as user 1 successfully
    let user0 = User::fetch_and_validate(
        &db,
        &users[0].email,
        &users[0].password,
        users[0].totp.code()?,
    )
    .await?;
    let user1 = User::fetch_and_validate(
        &db,
        &users[1].email,
        &users[1].password,
        users[1].totp.code()?,
    )
    .await?;

    // attempt to create a sessions
    let session_u0 = Session::create(&db, &user0, [192, 168, 0, 100].into()).await?;
    let session_u1 = Session::create(&db, &user1, [192, 168, 0, 101].into()).await?;

    assert!(
        !session_u0.is_expired(),
        "sessions should not start expired"
    );

    assert!(
        !session_u1.is_expired(),
        "sessions should not start expired"
    );

    // wait one seconds then expire the session
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

#[tokio::test]
async fn user_bad_password() -> eyre::Result<()> {
    let (db, users) = crate::tests::setup().await?;

    // login as user 1
    let user = &users[0];
    let r = User::fetch_and_validate(&db, &user.email, "invalid", user.totp.code()?).await;
    assert!(r.is_err(), "user logged in with invalid password");

    Ok(())
}

#[tokio::test]
async fn user_bad_otp() -> eyre::Result<()> {
    let (db, users) = crate::tests::setup().await?;

    // login as user 1
    let user = &users[0];
    let code = user.totp.code()? + 1; // make user code is wrong
    let r = User::fetch_and_validate(&db, &user.email, &user.password, code).await;
    assert!(r.is_err(), "user logged in with invalid otp");

    Ok(())
}

#[tokio::test]
async fn user_bad_password_and_otp() -> eyre::Result<()> {
    let (db, users) = crate::tests::setup().await?;

    // login as user 1
    let user = &users[0];
    let code = user.totp.code()? + 1; // make user code is wrong
    let r = User::fetch_and_validate(&db, &user.email, "invalid", code).await;
    assert!(r.is_err(), "user logged in with invalid otp");

    Ok(())
}
