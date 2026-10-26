package com.capstone.vuln.attack;

/**
 * 공격별 성공 판정기 공통 인터페이스
 * - 취약점 로직에는 관여하지 않고, 응답이 나온 뒤 결과를 "관찰"만 한다
 */
public interface AttackValidator<C> {

    AttackScenario scenario();

    AttackObservation validate(ValidationContext<C> ctx);
}
