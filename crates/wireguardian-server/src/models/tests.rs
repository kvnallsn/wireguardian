//! Integration Tests

use crate::models::{Dhcp, Session, User};
use color_eyre::eyre;
use std::time::Duration;
use uuid::Uuid;

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
    let mut session = Session::create(&db, &r).await?;
    assert!(!session.is_expired(), "sessions should not start expired");

    // acquire a dhcp lease for the session
    let lease_id = Uuid::new_v4();
    let lease = Dhcp::create(&db, lease_id, &session, [192, 168, 0, 100].into()).await?;
    assert!(lease.is_active(), "lease should be active when created");

    // wait one seconds then expire the lease
    lease.release(&db).await?;

    // fetch lesae to make sure it's now released
    let lease = Dhcp::fetch(&db, lease_id).await?;
    assert!(!lease.is_active(), "lease should be marked as released");

    // wait one seconds then expire the session
    tokio::time::sleep(Duration::from_secs(1)).await;
    session.expire(&db).await?;
    assert!(
        session.is_expired(),
        "session not expired when it should be"
    );

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
    let mut session_u0 = Session::create(&db, &user0).await?;
    let mut session_u1 = Session::create(&db, &user1).await?;

    assert!(
        !session_u0.is_expired(),
        "sessions should not start expired"
    );

    assert!(
        !session_u1.is_expired(),
        "sessions should not start expired"
    );

    // acquire a dhcp lease for the session
    let lease_id_u0 = Uuid::new_v4();
    let lease_u0 = Dhcp::create(&db, lease_id_u0, &session_u0, [192, 168, 0, 100].into()).await?;

    let lease_id_u1 = Uuid::new_v4();
    let lease_u1 = Dhcp::create(&db, lease_id_u1, &session_u1, [192, 168, 0, 101].into()).await?;

    assert!(lease_u0.is_active(), "leases should be active when created");
    assert!(lease_u1.is_active(), "leases should be active when created");

    lease_u0.release(&db).await?;
    lease_u1.release(&db).await?;

    // wait one seconds then expire the session
    tokio::time::sleep(Duration::from_secs(1)).await;
    session_u0.expire(&db).await?;
    session_u1.expire(&db).await?;

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
