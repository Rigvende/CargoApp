import React, {useEffect, useState} from "react";
import Paper from "@material-ui/core/Paper";
import Table from "@material-ui/core/Table";
import TableBody from "@material-ui/core/TableBody";
import TableCell from "@material-ui/core/TableCell";
import TableContainer from "@material-ui/core/TableContainer";
import TableHead from "@material-ui/core/TableHead";
import TablePagination from "@material-ui/core/TablePagination";
import TableRow from "@material-ui/core/TableRow";
import Button from "@material-ui/core/Button";
import EditIcon from "@material-ui/icons/Edit";
import DeleteIcon from "@material-ui/icons/Delete";
import fetchFieldFromObject from "../../../parts/util/fetch-field-from-object";

const columns = [
    {label: "Name", id: "name", minWidth: 100, maxWidth: 100, align: "center"},
    {label: "Mass", id: "mass", minWidth: 80, maxWidth: 80, align: "center"},
    {label: "Mass measure", id: "massMeasure", minWidth: 80, maxWidth: 80, align: "center"},
    {label: "Quantity", id: "quantity", minWidth: 80, maxWidth: 80, align: "center"},
    {label: "Quantity measure", id: "quantityMeasure", minWidth: 80, maxWidth: 80, align: "center"},
    {label: "Price", id: "price", minWidth: 100, maxWidth: 100},
    {label: "Currency", id: "currency", minWidth: 80, maxWidth: 80, align: "center"},
    {label: "Sum", id: "sum", minWidth: 100, maxWidth: 100, align: "center"},
    {id: "editDelete", label: "", minWidth: 60, maxWidth: 60, align: "center"}
];


export default (props) => {
    const onRowClick = props.onRowClick;
    const products = props.products;
    const changeTotal = props.onAddProduct;
    const {onRowDelete} = props;

    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(10);

    const TOTAL = {
        BYN: 0,
        USD: 0,
        EURO: 0,
        RUB: 0,
        weight: 0,
        quantity: 0
    };

    useEffect(() => {
        changeTotal(TOTAL);
    }, [props.products]);

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

    const handleChangeTotal = (price, currency, weight, measure, quantity) => {
        TOTAL[currency] = TOTAL[currency] + price;
        TOTAL.quantity = TOTAL.quantity + quantity;

        switch (measure) {
            case "KG":
                TOTAL.weight = TOTAL.weight + weight;
                break;
            case "TON":
                TOTAL.weight = TOTAL.weight + 1000 * weight;
        }

    };

    return (
        <Paper>
            <TableContainer>
                <Table aria-label="sticky table">
                    <TableHead>
                        <TableRow>
                            {columns.map((column) => (
                                <TableCell
                                    key={column.id}
                                    align={column.align}
                                    style={{maxWidth: column.maxWidth}}
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

                                const sumRow = Number(product.quantity) * Number(product.price);
                                handleChangeTotal(sumRow, product.currency, Number(product.mass), product.massMeasure, Number(product.quantity));

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

                                            if (column.id === "editDelete") {
                                                return (
                                                    <TableCell key={column.id} align={column.align}
                                                               className="edit-delete-block">
                                                        <Button
                                                            className="basket-table-btn"
                                                            color={"primary"}
                                                            startIcon={<EditIcon/>}
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                handleTableRowClick(product)
                                                            }}/>

                                                        <Button
                                                            className="basket-table-btn"
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                onRowDelete(product.id);
                                                            }} color="primary"
                                                            startIcon={<DeleteIcon/>}
                                                        />


                                                    </TableCell>
                                                );
                                            }

                                            let innerContent = column.id === "sum" ?
                                                sumRow + " " + product.currency :
                                                fetchFieldFromObject(product, column.id);

                                            return (
                                                <TableCell key={column.id} align={column.align}>
                                                    {innerContent}
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
