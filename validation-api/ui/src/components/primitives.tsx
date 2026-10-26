import { useLayoutEffect, useRef } from 'react';

// 도넛은 v8 과 같이 SVG 원호로 직접 그린다(vega 아님).
// stroke-dasharray/stroke/transform 은 SVG presentation attribute 라 CSP(style-src 'self') 에 걸리지 않는다.

interface DonutProps {
  /** 비율 0..1. null 이면 "데이터 없음"(점선 트랙). */
  value: number | null;
  color: string;
  size?: number;
  centerText: string;
  ariaLabel: string;
}

export function Donut({ value, color, size = 152, centerText, ariaLabel }: DonutProps) {
  const has = value != null && Number.isFinite(value);
  const filled = has ? Math.max(0, Math.min(100, value! * 100)) : 0;
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={ariaLabel}>
      {has ? (
        <>
          <circle cx="60" cy="60" r="45" fill="none" stroke="#ffffff1a" strokeWidth="18" />
          <circle
            cx="60" cy="60" r="45" fill="none" stroke={color} strokeWidth="18"
            pathLength={100} strokeDasharray={`${filled} ${100 - filled}`} transform="rotate(-90 60 60)"
          />
        </>
      ) : (
        <circle cx="60" cy="60" r="45" fill="none" stroke="#ffffff33" strokeWidth="16" strokeDasharray="4 4" />
      )}
      <text x="60" y="64" textAnchor="middle" fill={has ? '#ffffff' : '#ffffff99'} fontSize="16" fontWeight="700" fontFamily="Inter, sans-serif">
        {centerText}
      </text>
    </svg>
  );
}

// 세로 막대(건수). 높이·색을 ref 로 적용(프로그램 방식 style — CSP 미적용).
export function Bar({ heightPct, color, className = 'dbar' }: { heightPct: number; color: string; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (ref.current) {
      ref.current.style.height = `${Math.max(0, Math.min(100, heightPct))}%`;
      ref.current.style.background = color;
    }
  }, [heightPct, color]);
  return <div className={className} ref={ref} />;
}

// 가로 채움(비율 막대).
export function Meter({ widthPct, color, trackClass = 'meter-track', fillClass = 'meter-fill' }: { widthPct: number; color: string; trackClass?: string; fillClass?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    if (ref.current) {
      ref.current.style.width = `${Math.max(0, Math.min(100, widthPct))}%`;
      ref.current.style.background = color;
    }
  }, [widthPct, color]);
  return <div className={trackClass}><span className={fillClass} ref={ref} /></div>;
}

// 타임라인 이벤트 마커(left 위치).
export function EventMarker({ leftPct, color }: { leftPct: number; color: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    if (ref.current) {
      ref.current.style.left = `${leftPct}%`;
      ref.current.style.background = color;
    }
  }, [leftPct, color]);
  return <span className="ev" ref={ref} />;
}
