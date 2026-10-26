import { ratioBlock, type RatioInput } from '../lib/ratio';

interface Props extends RatioInput {
  /** 지표 이름(접근성/문맥용). */
  label?: string;
  className?: string;
}

/**
 * R-b 비율 표시. % 는 크게, 바로 아래 보조 "x건 중 y건 · 95% 신뢰도 a–b%"(Wilson).
 * % 만 단독으로 내보내지 않는다. n=0·차단·비-VALID 는 각각 안내문으로 대체.
 */
export function RatioBlock(props: Props) {
  const { label, className, ...input } = props;
  const m = ratioBlock(input);
  const aria = label ? `${label}: ${m.ariaCount}` : m.ariaCount;
  return (
    <div className={`rb rb-${m.kind}${className ? ' ' + className : ''}`} role="group" aria-label={aria}>
      <div className="rb-primary">{m.primary}</div>
      {m.aux ? <div className="rb-aux">{m.aux}</div> : null}
    </div>
  );
}
