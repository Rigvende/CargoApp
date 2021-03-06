import React from "react";
import Dialog from "@material-ui/core/Dialog";
import DialogContent from "@material-ui/core/DialogContent";
import {DialogTitleCustomized} from "../../parts/dialogs/dialog-title-customized";
import {ActForm} from "../../forms/act-form/act-form";

export default function ActDialog(props) {
    const invoice = props.waybill.invoice;
    return (
        <div>
            <Dialog
                fullWidth="true"
                maxWidth="md"
                open={props.open}
                onClose={props.onClose}
                aria-labelledby="form-dialog-title"
            >
                <DialogTitleCustomized
                    onClose={props.onClose}>
                    {"Act to invoice # " + invoice.number}
                </DialogTitleCustomized>
                <DialogContent>
                    <ActForm invoice={invoice} onSave={props.onSave} onClose={props.onClose}/>
                </DialogContent>
            </Dialog>
        </div>
    );
}