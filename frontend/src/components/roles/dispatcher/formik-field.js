import React from "react";
import TextField from "@material-ui/core/TextField";
import {ErrorMessage} from "formik";

export default function FormikField(props) {
    const {formikProps, formikFieldName, id, label} = props;
    return (
        <React.Fragment>
            <TextField
                margin="dense"
                id={id}
                label={label}
                type="text"
                onChange={formikProps.handleChange}
                onBlur={formikProps.handleBlur}
                value={formikProps.values[formikFieldName]}
                fullWidth
            />
            <label className="error-message">
                <ErrorMessage name={formikFieldName}/>
            </label>
        </React.Fragment>
    );
};
