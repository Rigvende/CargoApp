import {withRouter} from "react-router-dom";
import React from "react";
import {OkButton} from "../buttons/ok-button";
import {CancelButton} from "../buttons/cancel-button";
// import {updatePoint} from "../../roles/driver/request-utils";

export const PassPoint = withRouter((props) => {
    const handlePass = async () => {
        const selectedPoint = props.selected;
        // await updatePoint(selectedPoint); // TODO make request from parts/request-util
        // props.updatePoints();
        props.handleClose();
    };

    return (
        <div className="form-signin">
            <div>
                <i style={{fontSize: 16}}>Assign the point as "passed"?</i>
                <div className='btn-row'>
                    <OkButton content='OK' handleClick={handlePass}/>
                    <CancelButton content='Cancel' handleClick={props.handleClose}/>
                </div>
            </div>
        </div>);
})