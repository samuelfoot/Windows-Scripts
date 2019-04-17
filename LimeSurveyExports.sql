BEGIN
	SET @rowcount_Table1=(select count(*) from rar_tmp);
	set @rowcount_Table2=(select count(*) from lime_survey_785728);

	if @rowcount_Table1=@rowcount_table2 then
		select 'Both tables have identical data';
	else
		SET @rowcount_Table1=@rowcount_Table1+1;
		WHILE @rowcount_Table1 <= @rowcount_table2 DO
            		SET @qry=CONCAT('select * INTO OUTFILE "/var/lib/mysql-files/', @rowcount_Table1 ,'.csv" FIELDS TERMINATED BY "," from lime_survey_785728 where id = ', @rowcount_Table1, ';');
            		PREPARE `stmt` FROM @`qry`;
            		EXECUTE `stmt`;
            		DEALLOCATE PREPARE `stmt`;
            		SET @rowcount_Table1=@rowcount_Table1+1;
		END WHILE;
        
		TRUNCATE TABLE rar_tmp;
        	INSERT INTO rar_tmp
        	select * from lime_survey_785728;
	end if;
END
