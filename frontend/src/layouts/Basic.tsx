import { Box, Theme, useTheme } from "@mui/material";
import { Outlet } from "react-router-dom";
import { createStyles } from "@mui/styles";
import Header from "../components/header";
import Footer from "../components/footer";

const useStyle = (theme: Theme) => createStyles({
  root: {
    backgroundColor: 'var(--background-color)',
    // height: '100vh',
    width: '100vw',
    overflowX: 'hidden',
    [theme.breakpoints.up('md')]: {
      backgroundColor: 'white',
    },
  },
});

const Basic = () => {
  const theme = useTheme();
  const styles = useStyle(theme);
  return (
    <Box sx={styles.root}>
      <Header/>
      <Outlet />
      <Footer />
    </Box>
  );
};

export default Basic;
