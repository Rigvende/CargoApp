import Paper from "@material-ui/core/Paper";
import TableContainer from "@material-ui/core/TableContainer";
import Table from "@material-ui/core/Table";
import TableHead from "@material-ui/core/TableHead";
import TableRow from "@material-ui/core/TableRow";
import TableCell from "@material-ui/core/TableCell";
import TableBody from "@material-ui/core/TableBody";
import TablePagination from "@material-ui/core/TablePagination";
import React from "react";
import {Typography} from "@material-ui/core";
import {List} from "material-ui";
import ListItem from "@material-ui/core/ListItem";
import ListItemIcon from "@material-ui/core/ListItemIcon";
import ListItemText from "@material-ui/core/ListItemText";
import HowToRegIcon from '@material-ui/icons/HowToReg';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import DepartureBoardIcon from '@material-ui/icons/DepartureBoard';
import {getPointById, updatePoint} from "./request-utils";
import fetchFieldFromObject from "../../forms/fetch-field-from-object";
import CheckIcon from "@material-ui/icons/Check";

const columns = [
    {id: "place", label: "Place", minWidth: 200},
    {id: "passageDate", label: "Passage Date", minWidth: 200},
    {id: "passed", label: "Passed", minWidth: 200}
];

export default function WaybillInfoContent(props) {
    const [page, setPage] = React.useState(0);
    const [rowsPerPage] = React.useState(10);

    const handleTableRowClick = async (p) => {
        let selected = await getPointById(p.id);
        //fixme вставить диалог подтвердить прохождение точки on
        if (!selected.passed) {
            await updatePoint(selected);
            props.action();
        }
    };

    const handleChangePage = (event, newPage) => {
        setPage(newPage);
    };
    return (
        <div>
            <Paper>
                <List style={{alignItems: "flex-start"}}>
                    <div style={{display: "flex", flexDirection: "row"}}>
                        <ListItem style={{flexDirection: "column", alignItems: "flex-start"}}>
                            <ListItemIcon>
                                <CheckCircleIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Invoice #"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.invoice.number}
                                    </React.Fragment>
                                }
                            />
                            <ListItemIcon>
                                <CheckCircleIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Auto"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.auto.mark} {props.waybill.auto.type}
                                    </React.Fragment>
                                }
                            />
                            <ListItemIcon>
                                <CheckCircleIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Driver"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.driver.name} {props.waybill.driver.surname}
                                    </React.Fragment>
                                }
                            />
                        </ListItem>
                        <ListItem style={{flexDirection: "column", alignItems: "flex-start"}}>
                            <ListItemIcon>
                                <DepartureBoardIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Departure Date"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.departureDate}
                                    </React.Fragment>
                                }
                            />
                            <ListItemIcon>
                                <DepartureBoardIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Arrival Date"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.arrivalDate}
                                    </React.Fragment>
                                }
                            />
                        </ListItem>
                        <ListItem style={{flexDirection: "column", alignItems: "flex-start"}}>
                            <ListItemIcon>
                                <HowToRegIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Shipper"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.shipper}
                                    </React.Fragment>
                                }
                            />
                            <ListItemIcon>
                                <HowToRegIcon/>
                            </ListItemIcon>
                            <ListItemText
                                primary="Consignee"
                                secondary={
                                    <React.Fragment>
                                        {props.waybill.consignee}
                                    </React.Fragment>
                                }
                            />
                        </ListItem>
                    </div>
                </List>
                <TableContainer>
                    <Typography variant="h6"
                                gutterBottom
                                style={{textAlign: "center", marginTop: 15, marginLeft: 15}}>
                        Control Points:
                    </Typography>
                    <Table
                        aria-label="sticky table">
                        <TableHead>
                            <TableRow>
                                {columns.map((column) => (
                                    <TableCell
                                        key={column.id}
                                        style={{minWidth: column.minWidth, fontSize: 16, color: "#3f51b5"}}
                                    >
                                        {column.label}
                                    </TableCell>
                                ))}
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {props.waybill.points
                                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                                .map((point) => {
                                    return (
                                        <TableRow
                                            onClick={() => {
                                                handleTableRowClick(point);
                                            }}
                                            hover
                                            role="checkbox"
                                            tabIndex={-1}
                                            key={point.id}
                                        >
                                            {columns.map((column) => {
                                                const value = fetchFieldFromObject(point, column.id);
                                                return (
                                                    <TableCell key={column.id}>
                                                        {column.id === 'passed' && value === true
                                                            ? <CheckIcon/>
                                                            : column.id === 'passed' && value === false
                                                                ? ""
                                                                : value}
                                                    </TableCell>

                                                );
                                            })}
                                        </TableRow>
                                    );
                                })}
                        </TableBody>
                    </Table>
                </TableContainer>
                <br/>
                <TablePagination
                    rowsPerPageOptions={[5, 10, 15]}
                    component="div"
                    count={props.waybill.points.length}
                    rowsPerPage={rowsPerPage}
                    page={page}
                    onChangePage={handleChangePage}
                />
            </Paper>
        </div>
    );
}