import { createRoute } from "@tanstack/react-router";

import { calibration } from "../calibration-data";
import { rootRoute } from "./__root";

export function CalibrationPage() {
  return (
    <section aria-label="Calibration">
      <h1>Calibration</h1>
      <dl>
        <dt>Suite</dt>
        <dd>{calibration.suite_id}</dd>
        <dt>n</dt>
        <dd>{calibration.n}</dd>
        <dt>ok</dt>
        <dd>{calibration.ok}</dd>
        <dt>pass_k</dt>
        <dd>{calibration.pass_k}</dd>
        <dt>cost_usd</dt>
        <dd>{calibration.cost_usd}</dd>
      </dl>
      <table>
        <thead>
          <tr>
            <th>Expected</th>
          </tr>
        </thead>
        <tbody>
          {calibration.rows.map((row) => (
            <tr key={row.expected}>
              <td>{row.expected}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export const calibrationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/calibration",
  component: CalibrationPage,
});
