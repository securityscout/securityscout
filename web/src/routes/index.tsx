import { useQuery } from "@tanstack/react-query";
import { createRoute, Link } from "@tanstack/react-router";

import { engagement } from "../fixtures";
import { rootRoute } from "./__root";

export function EngagementsPage() {
  const { data: rows } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => [engagement],
    initialData: [engagement],
  });

  return (
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Org</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.id}>
            <td>
              <Link to="/engagements/$engId" params={{ engId: row.id }}>
                {row.id}
              </Link>
            </td>
            <td>{row.name}</td>
            <td>{row.org}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: EngagementsPage,
});
