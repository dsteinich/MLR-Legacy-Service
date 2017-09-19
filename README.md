# MLR-Legacy-Service
Monitoring Location Legacy CRU Service

## Database Configuration
You will need a postgreSQL database to run this application. A Dockerized version is available at https://github.com/USGS-CIDA/MLR_Legacy_DB.
The connection configuration is located in src/main/results/application.yml. You will need to create an application.yml file in your local project's root directory to provide the variable values. It should contain:

```
mlrLegacyDbHost: localhost
mlrLegacyDbPort: 5435
mlrLegacyDataUsername: mlr_legacy_data
mlrLegacyDataPassword: changeMe
mlrLegacyServicePassword: changeMe
```

## Automated Testing
This application has two flavors of automated tests: unit tests (in the gov.usgs.wma.mlrlegacy package) and integration tests (in the gov.usgs.wma.mlrlegacy.db package) requiring a database. The unit tests can be run in isolation according to your normal practices.
The integration tests can be run in a terminal with the maven command ```mvn verify``` in the project's root directory. Running in this manner will pull the database Docker image from the central repository and run it in a container.
They can also be run in your IDE against a database accessible to you. (Note that you should not use a shared database as the tests will destroy data and may have contention issues with other processes accessing the database.)
In either case, configuration information will be pulled from the maven setting.xml file. It will need to contain the following profile:
```
  <profile>
    <id>it</id>
    <properties>
      <postgresPassword>changeMe</postgresPassword>
      <mlrLegacyPassword>changeMe</mlrLegacyPassword>
      <mlrLegacyDataPassword>changeMe</mlrLegacyDataPassword>
      <mlrLegacyUserPassword>changeMe</mlrLegacyUserPassword>
      <mlrLegacyDataUsername>mlr_legacy_data</mlrLegacyDataUsername>
      <mlrLegacyServicePassword>changeMe</mlrLegacyServicePassword>
    </properties>
  </profile>
```

## Running the Application
Open a terminal window and navigate to the project's root directory.
Use the maven command ```mvn spring-boot:run``` to run the application.
It will be available at http://localhost:8080/monitoringLocations in you browser.

Swagger documentation is available at http://localhost:8080/swagger-ui.html

ctrl-c will stop the application.

## Using Docker
To build the image you will need to provide the location of the jar within 
https://cida.usgs.gov/artifactory/mlr-maven/gov/usgs/wma/mlrLegacy as follows:
``` 
% docker build --build-arg=0.1-SNAPSHOT/mlrLegacy-0.1-20170816.160616-1.jar .
```

To run the image, you will need to provide as environment variables the variables listed above. The application
will be available on part 8080 within the container.
