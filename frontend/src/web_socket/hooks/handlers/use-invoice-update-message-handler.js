import React from "react";
import {INVOICE_NOTIFICATION_DATA_URL, makeRequest} from "../../../components/parts/util/request-util";
import useInvoiceConfirmationForm from "../forms/use-invoice-confirmation-form";

const TOAST_TITLE = "Invoice was updated"

export default function useInvoiceUpdateMessageHandler() {
    const [InvoiceConfirmationDialogComponent, openInvoiceConfirmationDialogComponent] = useInvoiceConfirmationForm();

    const loadInvoiceNotificationData = (invoiceId) => {
        return makeRequest("GET", INVOICE_NOTIFICATION_DATA_URL + "/" + invoiceId);
    }

    const convertToStringAndFormat = (invoiceNotificationData) => {
        const data = invoiceNotificationData;
        return [
            "Number: ", <strong>{data.number}</strong>,
            <br/>,
            "Driver: ", <strong>{data.driver.name} {data.driver.surname}</strong>,
            <br/>,
            "Registered by: ", <strong>{data.registrationUser.name} {data.registrationUser.surname}</strong>,
            <br/>,
            "Status: ", <strong>{data.status}</strong>,
        ]
    }

    const handleInvoiceUpdateMessage = async (messageData, openActionToast) => {
        let response = await loadInvoiceNotificationData(messageData.invoiceId);
        let formatData = convertToStringAndFormat(response.data);
        openActionToast(TOAST_TITLE, formatData, () => openInvoiceConfirmationDialogComponent(messageData.invoiceId))
    }

    return [InvoiceConfirmationDialogComponent, handleInvoiceUpdateMessage]
}