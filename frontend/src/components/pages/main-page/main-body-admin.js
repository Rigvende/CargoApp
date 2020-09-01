import Typography from "@material-ui/core/Typography";
import React from "react";

export default function MainBodyAdmin(props) {
    const classes = props.classes;
    return <Typography
            className={classes.mainParagraph}
            paragraph>WELCOME TO CARGO MANAGER!
            </Typography>
}