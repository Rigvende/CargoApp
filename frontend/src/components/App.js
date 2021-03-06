import React from "react";
import "./App.css";
import interceptors from "../security/interceptors";
import {Redirect, Route, Switch} from "react-router-dom";
import {NotFound} from "./pages/error-page/error-404";
import {Header} from "./parts/layout/header";
import CssBaseline from "@material-ui/core/CssBaseline";
import {DrawerMenu} from "./parts/layout/drawer";
import WelcomeBody from "./pages/welcome-body";
import {Footer} from "./parts/layout/footer";
import {MainBody} from "./pages/main-body";
import {WaybillsTable} from "./roles/driver/waybills-table"
import InfoBody from "./pages/info-body";
import ContactsBody from "./pages/contacts-body";
import InvoicesTable from "./roles/manager/invoices-table";
import {UserTable} from "./roles/admin/users/user-table";
import {ProductOwnersTable} from "./roles/dispatcher/product-owners/product-owners-table";
import {AutoTable} from "./roles/admin/autos/auto-table";
import {StorageTable} from "./roles/dispatcher/storages/storages-table";
import {ClientsTable} from "./roles/sysadmin/clients-table";
import PrivateRoute from "../security/private-route";
import {
    ROLE_ADMIN,
    ROLE_DISPATCHER,
    ROLE_MANAGER,
    ROLE_DRIVER,
    ROLE_OWNER,
    ROLE_SYSADMIN
} from "../security/private-route";
import {ProfileInfo} from "./pages/profile-info";
import CurrentWaybillBody from "./pages/current-waybill-page";
import {WebSocket} from "../web_socket/web-socket";
import RegistrationForm from "./forms/registration/registration-form";
import ChangePasswordForm from "./forms/reset-password-form/reset-password";
import {Greeting} from "./parts/greeting/greeting";
import {OwnerContent} from "./roles/owner/owner-content";
import {CalendarTable} from "./roles/manager/calendar-table";
import {TokenParser} from "./pages/oauth-jwt-token-parse";
import {UserNotExist} from "./pages/error-page/error-oauth2-denied";


export default function App() {
    const [openMenu, setOpenMenu] = React.useState(false);

    const handleMenuOpen = () => {
        setOpenMenu(true);
    };
    const handleMenuClose = () => {
        setOpenMenu(false);
    };

    return (
        <div className="App">
            <div className="App-body">
                <Header
                    openMenu={openMenu}
                    handleDrawerOpen={handleMenuOpen}
                />
                <DrawerMenu
                    openMenu={openMenu}
                    handleDrawerClose={handleMenuClose}
                />
                <Switch>
                    <Route exact path="/" component={WelcomeBody}/>
                    <Route exact path="/info" component={InfoBody}/>
                    <Route exact path="/contacts" component={ContactsBody}/>
                    <Route exact path="/jwt-parser" component={TokenParser}/>
                    <Route exact path="/registration" component={RegistrationForm}/>
                    <Route exact path="/password" component={ChangePasswordForm}/>
                    <PrivateRoute exact path="/main" component={MainBody}/>
                    <PrivateRoute exact path="/profile" component={ProfileInfo}/>
                    <PrivateRoute exact path="/waybill" component={WaybillsTable}
                                  hasAnyAuthorities={[ROLE_MANAGER, ROLE_OWNER, ROLE_DRIVER]}/>
                    <PrivateRoute exact path={"/calendar"} component={CalendarTable}
                                  hasAnyAuthorities={[ROLE_OWNER, ROLE_MANAGER]}/>
                    <PrivateRoute exact path={"/invoice"} component={InvoicesTable}
                                  hasAnyAuthorities={[ROLE_MANAGER, ROLE_OWNER, ROLE_DRIVER, ROLE_DISPATCHER]}/>
                    <PrivateRoute exact path={"/users"} component={UserTable}
                                  hasAnyAuthorities={[ROLE_ADMIN, ROLE_OWNER]}/>
                    <PrivateRoute exact path={"/autos"} component={AutoTable}
                                  hasAnyAuthorities={[ROLE_DISPATCHER, ROLE_ADMIN, ROLE_OWNER]}/>
                    <PrivateRoute exact path={"/owners"} component={ProductOwnersTable}
                                  hasAnyAuthorities={[ROLE_DISPATCHER, ROLE_OWNER]}/>
                    <PrivateRoute exact path={"/storages"} component={StorageTable}
                                  hasAnyAuthorities={[ROLE_DISPATCHER, ROLE_ADMIN, ROLE_OWNER]}/>
                    <PrivateRoute exact path={"/current"} component={CurrentWaybillBody}
                                  hasAnyAuthorities={[ROLE_DRIVER]}/>
                    <PrivateRoute exact path={"/reports"} component={OwnerContent}
                                  hasAnyAuthorities={[ROLE_OWNER]}/>
                    <Route exact path={"/success"}><Redirect to={"/main"}/></Route>
                    <PrivateRoute exact path={"/clients"} component={ClientsTable} hasAnyAuthorities={[ROLE_SYSADMIN]}/>
                    <Route exact path={"/error-oauth-denied"} component={UserNotExist}/>
                    <Route component={NotFound}/>
                </Switch>
                <WebSocket/>
                <Greeting/>
                <CssBaseline/>
                <Footer/>
            </div>
        </div>
    );
}

