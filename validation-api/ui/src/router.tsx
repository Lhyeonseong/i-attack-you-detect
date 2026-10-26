import { createBrowserRouter, Navigate, Outlet } from 'react-router-dom';
import { DashboardProvider } from './components/DashboardContext';
import Overview from './screens/Overview';
import Attacks from './screens/Attacks';
import Detail from './screens/Detail';
import Detection from './screens/Detection';
import Attck from './screens/Attck';
import System from './screens/System';
import Revalidate from './screens/Revalidate';
import Report from './screens/Report';

function Root() {
  return (
    <DashboardProvider>
      <Outlet />
    </DashboardProvider>
  );
}

export const router = createBrowserRouter([
  {
    element: <Root />,
    children: [
      { path: '/', element: <Navigate to="/overview" replace /> },
      { path: '/overview', element: <Overview /> },
      { path: '/attacks', element: <Attacks /> },
      { path: '/attempts/:id', element: <Detail /> },
      { path: '/detection', element: <Detection /> },
      { path: '/attck', element: <Attck /> },
      { path: '/system', element: <System /> },
      { path: '/revalidate', element: <Revalidate /> },
      { path: '/report', element: <Report /> },
      { path: '*', element: <Navigate to="/overview" replace /> },
    ],
  },
]);
