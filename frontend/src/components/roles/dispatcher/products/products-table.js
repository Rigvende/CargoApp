import React, {useState} from "react";
import {makeStyles} from "@material-ui/core/styles";
import Paper from "@material-ui/core/Paper";
import Table from "@material-ui/core/Table";
import TableBody from "@material-ui/core/TableBody";
import TableCell from "@material-ui/core/TableCell";
import TableContainer from "@material-ui/core/TableContainer";
import TableHead from "@material-ui/core/TableHead";
import TablePagination from "@material-ui/core/TablePagination";
import TableRow from "@material-ui/core/TableRow";
import fetchFieldFromObject from "../../../forms/fetch-field-from-object";

const columns = [
    {label: "Name", id: "name", minWidth: 100, maxWidth: 100},
    {label: "Measure", id: "measure", minWidth: 100, maxWidth: 100},
    {label: "Mass", id: "mass", minWidth: 100, maxWidth: 100},
    {label: "Quantity", id: "quantity", minWidth: 100, maxWidth: 100},
    {label: "Price", id: "price", minWidth: 100, maxWidth: 100},
];

const useStyles = makeStyles({
    root: {
        // width: "100%",
    },
    container: {
        maxHeight: 440,
    },
});

export default (props) => {
    const onRowClick = props.onRowClick;
    const products = props.products;

    const classes = useStyles();
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(10);

    const handleChangePage = (event, newPage) => {
        setPage(newPage);
    };

    const handleTableRowClick = (product) => {
        onRowClick(product);
    };

    const handleChangeRowsPerPage = (event) => {
        setRowsPerPage(+event.target.value);
        setPage(0);
    };

    return (
        <Paper className={classes.root}>
            <TableContainer className={classes.container}>
                <Table aria-label="sticky table">
                    <TableHead>
                        <TableRow>
                            {columns.map((column) => (
                                <TableCell
                                    key={column.id}
                                    style={{ maxWidth: column.maxWidth}}
                                >
                                    {column.label}
                                </TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {products
                            .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                            .map((product) => {
                                return (
                                    <TableRow
                                        onClick={() => {
                                            handleTableRowClick(product);
                                        }}
                                        hover
                                        role="checkbox"
                                        tabIndex={-1}
                                        key={product.id}
                                    >
                                        {columns.map((column) => {
                                            return (
                                                <TableCell key={column.id}>
                                                    {fetchFieldFromObject(product, column.id)}
                                                </TableCell>
                                            );
                                        })}
                                    </TableRow>
                                );
                            })}
                    </TableBody>
                </Table>
            </TableContainer>

            <TablePagination
                rowsPerPageOptions={[10, 25, 100]}
                component="div"
                count={products.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onChangePage={handleChangePage}
                onChangeRowsPerPage={handleChangeRowsPerPage}
            />
        </Paper>
    );
};
