import React, {useEffect, useState} from "react";
import {makeStyles} from "@material-ui/core/styles";
import {ListItem} from "material-ui/List";
import List from "@material-ui/core/List";
import {API_KEY} from "./abstract-map";
import {countDistanceBetweenMarkers, pointsComparator} from "./utils";

const useStyles = makeStyles((theme) => ({
    root: {
        width: 400,
        height: 500,
        overflow: 'auto',
        backgroundColor: theme.palette.background.paper,
    },
}));

export default function ItemList(props) {
    const classes = useStyles();
    const [geocodedPoints, setGeocodedPoints] = useState([]);
    const [distance, setDistance] = useState(0);

    const handleRowClick = (geocodedPoint) => {
        props.onRowClick(geocodedPoint.index);
    };

    const updateDistance = (points) => {
        setDistance(countDistanceBetweenMarkers(points) / 1000);
    }


    const isPointGeocoded = (point) => {
        for (let geocodedPoint of geocodedPoints) {
            if (geocodedPoint.index === point.index) {
                return true;
            }
        }
        return false;
    }

    const geocodeNewPoint = async (point) => {
        let geocodedPoint = await geocode(point.lat, point.lng);
        await setGeocodedPoints((prevState => {
            let points = prevState.slice();
            points.push({index: point.index, geocodedPoint});
            return points
        }))
    }

    const geocodeNewPoints = async (points) => {
        for (let point of points) {
            if (!isPointGeocoded(point)) {
                geocodeNewPoint(point)
            }
        }
    }

    const deleteGeocodePointByIndex = async (index) => {
        await setGeocodedPoints(prevState => {
            let points = prevState.slice();
            points.splice(index, 1);
            return points;
        })
    }

    const deleteGeocodedPoint = (points) => {
        let isPointDeleted;
        for (let i = 0; i < geocodedPoints.length; i++) {
            isPointDeleted = true;
            for (let point of points) {
                if (geocodedPoints[i].index === point.index) {
                    isPointDeleted = false;
                    break;
                }
            }
            if (isPointDeleted) {
                deleteGeocodePointByIndex(i);
                break;
            }
        }
    }

    const geocode = async (lat, lng) => {
        try {
            let response = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&language=en&key=${API_KEY}`)
            response = await response.json();
            return response.results[0].formatted_address;
        } catch (e) {
            console.error("Cannot geocode")
            return "Unrecognized place";
        }
    }

    useEffect(() => {
        if (props.items.length > geocodedPoints.length) {
            geocodeNewPoints(props.items)
        } else if (props.items.length < geocodedPoints.length) {
            deleteGeocodedPoint(props.items);
        }
        updateDistance(props.items)
    }, [props.items.length])

    return (
        <List className={classes.root}>
            <div align={"center"}>
                <h3>{props.listName + `  [${distance.toFixed(3)} km]`}</h3>
            </div>
            {geocodedPoints.sort(pointsComparator).map((point, key) => {
                return (
                    <ListItem
                        align={"left"}
                        primaryText={`[${key + 1}] ${point.geocodedPoint}`}
                        key={key}
                        onClick={() => handleRowClick(point)}
                    />
                );
            })}
        </List>
    );
}
