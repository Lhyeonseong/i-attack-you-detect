import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// R-j: WCAG 2.2 AA 스모크. 각 라우트에서 axe-core 위반 0 + 화면 testid 노출 확인.
const routes: Array<[string, string]> = [
  ['/overview', 'screen-overview'],
  ['/attacks', 'screen-attacks'],
  ['/attempts/a-01', 'screen-detail'],
  ['/detection', 'screen-detection'],
  ['/attck', 'screen-attck'],
  ['/system', 'screen-system'],
  ['/revalidate', 'screen-revalidate'],
  ['/report', 'screen-report'],
];

for (const [path, testid] of routes) {
  test(`접근성 위반 없음: ${path}`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByTestId(testid)).toBeVisible();
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();
    expect(results.violations).toEqual([]);
  });
}
