import * as Yup from "yup";

export const RejectInvoiceValidation = Yup.object({
    comment: Yup.string()
        .min(5, "Min length must be greater than 5 symbols")
        .max(500, "Max length must be lesser than 500 symbols")
        .required("Comment is required")
});