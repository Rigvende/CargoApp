import React, {useEffect} from "react";

export function TokenParser() {
    useEffect(() => {
        let href = window.location.href;
        let url = new URL(href);
        let jwttoken = url.searchParams.get("jwttoken");
        localStorage.setItem("authorization", jwttoken);
        alert(localStorage.getItem("authorization"));
        window.location.href = "http://localhost:3000/main";
    })
    return <div></div>
}